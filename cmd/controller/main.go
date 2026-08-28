/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	otellog "go.opentelemetry.io/otel/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/go-logr/logr"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/controller"
	"github.com/rancher-sandbox/network-enforcer/internal/events"
	"github.com/rancher-sandbox/network-enforcer/internal/flowdumper"
	"github.com/rancher-sandbox/network-enforcer/internal/istio"
	"github.com/rancher-sandbox/network-enforcer/internal/ringbuf"
	"github.com/rancher-sandbox/network-enforcer/internal/scraper"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/rancher-sandbox/network-enforcer/internal/violation"
	// +kubebuilder:scaffold:imports
)

const (
	defaultWnpStatusUpdateInterval = 30 * time.Second
	// otlpLogShutdownTimeout bounds the final flush of buffered log records
	// when the manager stops. The manager context is already cancelled at
	// that point, so the shutdown runs against a fresh context.
	otlpLogShutdownTimeout = 10 * time.Second
)

type otelConf struct {
	Endpoint   string
	Protocol   string
	CACert     string
	ClientCert string
	ClientKey  string
}

type metricsConf struct {
	Addr     string
	CertPath string
	CertName string
	CertKey  string
}

type providerConfig struct {
	name     string
	endpoint string
}

type config struct {
	metrics              metricsConf
	enableLeaderElection bool
	probeAddr            string
	secureMetrics        bool
	enableHTTP2          bool
	logLevel             string
	provider             providerConfig
	flowDumper           flowdumper.Config
	otel                 otelConf
	tlsOpts              []func(*tls.Config)
	wnpStatusSyncConfig  controller.WorkloadNetworkPolicyStatusSyncConfig
}

func parseLogLevel(level string) (slog.Level, error) {
	parsed := slog.LevelInfo
	if err := parsed.UnmarshalText([]byte(level)); err != nil {
		return 0, fmt.Errorf("invalid log level %q: %w", level, err)
	}
	return parsed, nil
}

func setupProviderScraper(
	ctx context.Context,
	logger *slog.Logger,
	mgr manager.Manager,
	conf *config,
	learningEnqueueFunc func(types.LearningEvent) bool,
	violationBuffer *ringbuf.Buffer[violation.Observation],
	flowDumperBuffer *ringbuf.Buffer[json.RawMessage],
	eventLogger otellog.Logger,
) error {
	providerName := types.Provider(conf.provider.name)
	logger.InfoContext(ctx, "Configuring scraper", "provider", providerName)
	switch providerName {
	case types.ProviderIstio:
		otelPort, err := strconv.Atoi(conf.provider.endpoint)
		if err != nil {
			return fmt.Errorf("istio provider: invalid OTEL port %q: %w", conf.provider.endpoint, err)
		}
		istioScraper := scraper.NewIstioScraper(scraper.IstioScraperConfig{
			ViolationBuffer:      violationBuffer,
			EnqueueLearningEvent: learningEnqueueFunc,
			ViolationOtelLogger:  eventLogger,
			Logger:               logger.With("component", "istio-scraper"),
			OtelPort:             otelPort,
			Enricher:             istio.NewEnricher(mgr.GetClient()),
			FlowDumperBuffer:     flowDumperBuffer,
		})
		if err = mgr.Add(istioScraper); err != nil {
			return fmt.Errorf("unable to add istio scraper to manager: %w", err)
		}
		return nil
	case types.ProviderCilium:
		ciliumScraper := scraper.NewCiliumScraper(scraper.CiliumScraperConfig{
			Client:               mgr.GetClient(),
			Logger:               logger.With("component", "cilium-scraper"),
			Endpoint:             conf.provider.endpoint,
			EnqueueLearningEvent: learningEnqueueFunc,
			ViolationBuffer:      violationBuffer,
			FlowDumperBuffer:     flowDumperBuffer,
		})
		if err := mgr.Add(ciliumScraper); err != nil {
			return fmt.Errorf("unable to add cilium scraper to manager: %w", err)
		}
		return nil
	case types.ProviderCalico:
		calicoScraper := scraper.NewCalicoScraper(scraper.CalicoScraperConfig{
			Endpoint:             conf.provider.endpoint,
			EnqueueLearningEvent: learningEnqueueFunc,
			Logger:               logger.With("component", "calico-scraper"),
			Client:               mgr.GetClient(),
			ViolationBuffer:      violationBuffer,
			FlowDumperBuffer:     flowDumperBuffer,
		})
		if err := mgr.Add(calicoScraper); err != nil {
			return fmt.Errorf("unable to add calico scraper to manager: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported provider %q", conf.provider.name)
	}
}

func newControllerManager(conf *config) (manager.Manager, error) {
	metricsServerOptions := metricsserver.Options{
		BindAddress:   conf.metrics.Addr,
		SecureServing: conf.secureMetrics,
		TLSOpts:       conf.tlsOpts,
	}

	if conf.secureMetrics {
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	if len(conf.metrics.CertPath) > 0 {
		metricsServerOptions.CertDir = conf.metrics.CertPath
		metricsServerOptions.CertName = conf.metrics.CertName
		metricsServerOptions.KeyName = conf.metrics.CertKey
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
	utilruntime.Must(istiosecurityv1.AddToScheme(scheme))
	controllerOptions := ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		HealthProbeBindAddress: conf.probeAddr,
		LeaderElection:         conf.enableLeaderElection,
		LeaderElectionID:       "6163c1ee.security.rancher.io",
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), controllerOptions)
	if err != nil {
		return nil, fmt.Errorf("unable to start manager: %w", err)
	}
	return mgr, nil
}

// setupOtelLogExporter initialises the OTLP log exporter and registers
// its shutdown runnable. Caller must ensure conf.otel.Endpoint is set.
func setupOtelLogExporter(
	ctx context.Context,
	logger *slog.Logger,
	mgr manager.Manager,
	otelCfg events.OTELConfig,
) (otellog.Logger, error) {
	eventLogger, eventShutdown, err := events.Init(ctx, otelCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OTLP log exporter: %w", err)
	}
	logger.InfoContext(ctx, "OTLP violation telemetry enabled",
		"endpoint", otelCfg.Endpoint,
		"protocol", otelCfg.Protocol)

	err = mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		<-ctx.Done()
		if eventShutdown != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), otlpLogShutdownTimeout)
			defer cancel()
			if sErr := eventShutdown(shutdownCtx); sErr != nil {
				logger.ErrorContext(ctx, "failed to shutdown OTLP log provider", "error", sErr)
			}
		}
		return nil
	}))
	if err != nil {
		return nil, fmt.Errorf("unable to register OTLP log shutdown runnable: %w", err)
	}
	return eventLogger, nil
}

func setupFlowDumper(
	logger *slog.Logger,
	mgr manager.Manager,
	conf *flowdumper.Config,
) (*ringbuf.Buffer[json.RawMessage], error) {
	flowDumperBuffer := ringbuf.NewWithSize[json.RawMessage](conf.BufferSize)
	flowDumper := flowdumper.New(flowDumperBuffer, logger, conf.Port)
	if err := mgr.Add(flowDumper); err != nil {
		return nil, fmt.Errorf("unable to add flow dumper to manager: %w", err)
	}
	return flowDumperBuffer, nil
}

func run(logger *slog.Logger, conf *config) error {
	ctx := ctrl.SetupSignalHandler()

	// Mitigate HTTP/2 Stream Cancellation / Rapid Reset CVEs.
	if !conf.enableHTTP2 {
		conf.tlsOpts = append(conf.tlsOpts, func(c *tls.Config) {
			c.NextProtos = []string{"http/1.1"}
		})
	}

	mgr, err := newControllerManager(conf)
	if err != nil {
		return fmt.Errorf("unable to create controller manager: %w", err)
	}

	// Enriching the source workload of an Istio violation is by peer IP, so
	// register the pod status.podIP index before the cache starts.
	if err = controller.SetupPodIPIndexer(ctx, mgr); err != nil {
		return fmt.Errorf("unable to set up pod IP indexer: %w", err)
	}

	var eventLogger otellog.Logger
	if conf.otel.Endpoint != "" {
		otelCfg := events.OTELConfig{
			Endpoint:   conf.otel.Endpoint,
			Protocol:   conf.otel.Protocol,
			CACert:     conf.otel.CACert,
			ClientCert: conf.otel.ClientCert,
			ClientKey:  conf.otel.ClientKey,
		}
		eventLogger, err = setupOtelLogExporter(ctx, logger, mgr, otelCfg)
		if err != nil {
			return err
		}
	}

	// Create the violation ring buffer shared
	violationBuffer := ringbuf.New[violation.Observation]()

	// Configure flowDumper if necessary
	var flowDumperBuffer *ringbuf.Buffer[json.RawMessage]
	flowDumperConf := conf.flowDumper
	if flowDumperConf.Enabled {
		logger.InfoContext(ctx, "Flow dumper enabled",
			"bufferSize", flowDumperConf.BufferSize,
			"port", flowDumperConf.Port,
		)
		if flowDumperBuffer, err = setupFlowDumper(logger, mgr, &flowDumperConf); err != nil {
			return err
		}
	}

	learningReconciler := controller.NewLearningReconciler(mgr.GetClient(), violationBuffer)
	if err = learningReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create learning reconciler: %w", err)
	}

	if err = setupProviderScraper(ctx,
		logger,
		mgr,
		conf,
		learningReconciler.GetEnqueueFunc(),
		violationBuffer,
		flowDumperBuffer,
		eventLogger,
	); err != nil {
		return err
	}

	if err = setupControllers(ctx, logger, mgr, conf, eventLogger, violationBuffer); err != nil {
		return err
	}

	if err = mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to add healthz check: %w", err)
	}
	if err = mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to add readyz check: %w", err)
	}

	logger.InfoContext(ctx, "starting manager")
	return mgr.Start(ctx)
}

func setupControllers(
	ctx context.Context,
	logger *slog.Logger,
	mgr manager.Manager,
	conf *config,
	eventLogger otellog.Logger,
	violationBuffer *ringbuf.Buffer[violation.Observation],
) error {
	if err := (&controller.WorkloadNetworkPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to setup WorkloadNetworkPolicyReconciler controller: %w", err)
	}

	if err := (&controller.WorkloadNetworkPolicyProposalReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to setup WorkloadNetworkPolicyProposal controller: %w", err)
	}

	conf.wnpStatusSyncConfig.EventLogger = eventLogger
	conf.wnpStatusSyncConfig.ViolationBuffer = violationBuffer
	logger.InfoContext(ctx, "Setting up WorkloadNetworkPolicyStatusSync with",
		"config", conf.wnpStatusSyncConfig)
	wnpStatusSync, err := controller.NewWorkloadNetworkPolicyStatusSync(
		mgr.GetClient(),
		&conf.wnpStatusSyncConfig,
	)
	if err != nil {
		return fmt.Errorf("unable to create WorkloadNetworkPolicyStatusSync: %w", err)
	}
	if err = mgr.Add(wnpStatusSync); err != nil {
		return fmt.Errorf("unable to add WorkloadNetworkPolicyStatusSync runnable: %w", err)
	}

	// +kubebuilder:scaffold:builder

	return nil
}

func main() {
	conf := &config{}
	flag.StringVar(&conf.metrics.Addr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&conf.probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&conf.enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&conf.secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&conf.metrics.CertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(
		&conf.metrics.CertName,
		"metrics-cert-name",
		"tls.crt",
		"The name of the metrics server certificate file.",
	)
	flag.StringVar(&conf.metrics.CertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&conf.enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics server")
	flag.StringVar(&conf.logLevel, "log-level", "info",
		"Log level for controller logs. Valid values: debug, info, warn, error.")
	flag.BoolVar(&conf.flowDumper.Enabled, "flow-dumper-enabled", false,
		"Enable flow debug collection and periodic file dumps.")
	flag.IntVar(&conf.flowDumper.Port, "flow-dumper-port", flowdumper.DefaultPort,
		"Port for the flow dumper HTTP server.")
	flag.IntVar(&conf.flowDumper.BufferSize, "flow-dumper-buffer-size", flowdumper.DefaultBufferSize,
		"In-memory ring buffer size for flow debug dumps.")
	flag.StringVar(&conf.provider.name, "provider-name", "",
		"Data-plane provider used by the controller. Valid values: istio, cilium, calico.")
	flag.StringVar(
		&conf.provider.endpoint,
		"provider-endpoint",
		"",
		"Provider endpoint",
	)
	flag.StringVar(&conf.otel.Endpoint, "otlp-log-endpoint",
		os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		"OTLP endpoint for the violation-lifecycle log exporter "+
			"(policy_violation_acknowledged records). Defaults to the "+
			"OTEL_EXPORTER_OTLP_ENDPOINT env var; empty disables OTLP logs.")
	otlpLogProtocolDefault := os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	if otlpLogProtocolDefault == "" {
		otlpLogProtocolDefault = "grpc"
	}
	flag.StringVar(&conf.otel.Protocol, "otlp-log-protocol",
		otlpLogProtocolDefault,
		"OTLP protocol for the violation-lifecycle log exporter: grpc or "+
			"http/protobuf. Defaults to OTEL_EXPORTER_OTLP_PROTOCOL env var or grpc.")
	flag.StringVar(&conf.otel.CACert, "otlp-log-ca-cert",
		os.Getenv("OTEL_EXPORTER_OTLP_CERTIFICATE"),
		"Path to the CA certificate for verifying the OTLP log collector's "+
			"TLS certificate. Defaults to the OTEL_EXPORTER_OTLP_CERTIFICATE env "+
			"var; empty means insecure.")
	flag.StringVar(&conf.otel.ClientCert, "otlp-log-client-cert",
		os.Getenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE"),
		"Path to the client TLS certificate for mTLS with the OTLP log "+
			"collector. Defaults to the OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE env var.")
	flag.StringVar(&conf.otel.ClientKey, "otlp-log-client-key",
		os.Getenv("OTEL_EXPORTER_OTLP_CLIENT_KEY"),
		"Path to the client TLS key for mTLS with the OTLP log collector. "+
			"Defaults to the OTEL_EXPORTER_OTLP_CLIENT_KEY env var.")
	flag.DurationVar(&conf.wnpStatusSyncConfig.UpdateInterval,
		"wnp-status-reconciler-update-interval",
		defaultWnpStatusUpdateInterval,
		"The interval at which WorkloadNetworkPolicy status is synced.")
	flag.Parse()

	parsedLogLevel, err := parseLogLevel(conf.logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse log level: %v\n", err)
		os.Exit(1)
	}
	slogHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parsedLogLevel})
	slogger := slog.New(slogHandler).With("component", "controller")
	slog.SetDefault(slogger)
	ctrl.SetLogger(logr.FromSlogHandler(slogger.Handler()))

	if err = run(slogger, conf); err != nil {
		slogger.Error("failed to run", "error", err)
		os.Exit(1)
	}
}
