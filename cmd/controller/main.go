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
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	otellog "go.opentelemetry.io/otel/log"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/go-logr/logr"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/certsource"
	"github.com/kubewarden/network-enforcer/internal/controller"
	"github.com/kubewarden/network-enforcer/internal/events"
	"github.com/kubewarden/network-enforcer/internal/flowdumper"
	"github.com/kubewarden/network-enforcer/internal/grpcexporter"
	"github.com/kubewarden/network-enforcer/internal/istio"
	"github.com/kubewarden/network-enforcer/internal/ringbuf"
	"github.com/kubewarden/network-enforcer/internal/scraper"
	"github.com/kubewarden/network-enforcer/internal/types"
	"github.com/kubewarden/network-enforcer/internal/types/otlp"
	"github.com/kubewarden/network-enforcer/internal/violation"
	// +kubebuilder:scaffold:imports
)

const (
	defaultWnpStatusUpdateInterval = 30 * time.Second
	// otlpLogShutdownTimeout bounds the final flush of buffered log records
	// when the manager stops. The manager context is already cancelled at
	// that point, so the shutdown runs against a fresh context.
	otlpLogShutdownTimeout = 10 * time.Second
)

type cacheSyncReadinessRunnable struct {
	cache  cache.Cache
	synced *atomic.Bool
}

func (r cacheSyncReadinessRunnable) Start(ctx context.Context) error {
	if !r.cache.WaitForCacheSync(ctx) {
		return nil
	}
	r.synced.Store(true)
	<-ctx.Done()
	return nil
}

func (cacheSyncReadinessRunnable) NeedLeaderElection() bool {
	return false
}

type otelConf struct {
	Endpoint string
	Protocol string
}

type metricsConf struct {
	Addr     string
	CertPath string
	CertName string
	CertKey  string
}

type providerConfig struct {
	name           string
	endpoint       string
	tlsMode        string
	tlsCertDir     string
	tlsCertSecret  string
	tlsCAConfigMap string
	tlsCABundleKey string
	tlsServerName  string
}

// certSourceConfig maps the provider TLS flags onto [certsource.Config].
func (p *providerConfig) certSourceConfig() certsource.Config {
	return certsource.Config{
		Mode:        certsource.Mode(p.tlsMode),
		CertDir:     p.tlsCertDir,
		CertSecret:  p.tlsCertSecret,
		CAConfigMap: p.tlsCAConfigMap,
		CABundleKey: p.tlsCABundleKey,
		ServerName:  p.tlsServerName,
	}
}

// agentConfig holds the controller client TLS flags for the agent hop.
// The agent is the gRPC server; the controller dials it. The client
// certificate is mounted as a directory. See RFC 0006 and ADR 0001.
type agentConfig struct {
	mtlsEnabled    bool
	certDirPath    string
	namespace      string
	labelSelector  string
	grpcPort       int
	pollInterval   time.Duration
	scrapeTimeout  time.Duration
	maxInFlight    int
	maxRecvMsgSize int
}

type config struct {
	metrics              metricsConf
	enableLeaderElection bool
	probeAddr            string
	secureMetrics        bool
	enableHTTP2          bool
	logLevel             string
	provider             providerConfig
	agent                agentConfig
	legacyIstioFlags     []string
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

// Reads through GetAPIReader so a cross-namespace Secret does not start a cluster-wide informer.
func newProviderCertSource(mgr manager.Manager, conf *config) (certsource.Source, error) {
	cfg := conf.provider.certSourceConfig()
	if cfg.Mode == certsource.ModeInsecure {
		return nil, nil //nolint:nilnil // an insecure hop has no certificate source
	}
	source, err := certsource.New(cfg, mgr.GetAPIReader())
	if err != nil {
		return nil, fmt.Errorf("unable to create provider TLS cert source: %w", err)
	}
	return source, nil
}

// newAgentClientFactory builds the controller client for the agent hop.
// The client certificate is loaded from a mounted directory and reloaded on
// each dial for rotation.
func newAgentClientFactory(conf *config) (*grpcexporter.AgentClientFactory, error) {
	factory, err := grpcexporter.NewAgentClientFactory(grpcexporter.AgentFactoryConfig{
		MTLSEnabled:    conf.agent.mtlsEnabled,
		CertDirPath:    conf.agent.certDirPath,
		Timeout:        conf.agent.scrapeTimeout,
		MaxRecvMsgSize: conf.agent.maxRecvMsgSize,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create agent client factory: %w", err)
	}
	return factory, nil
}

func explicitlySetProviderFlags(fs *flag.FlagSet) []string {
	legacy := map[string]bool{
		"provider-endpoint":          true,
		"provider-tls-mode":          true,
		"provider-tls-cert-dir":      true,
		"provider-tls-cert-secret":   true,
		"provider-tls-ca-configmap":  true,
		"provider-tls-ca-bundle-key": true,
		"provider-tls-server-name":   true,
	}
	var explicitlySet []string
	fs.Visit(func(f *flag.Flag) {
		if legacy[f.Name] {
			explicitlySet = append(explicitlySet, f.Name)
		}
	})
	return explicitlySet
}

// validateCalicoTLSMode rejects plaintext; Goldmane requires mTLS.
func validateCalicoTLSMode(tlsMode string) error {
	if certsource.Mode(tlsMode) == certsource.ModeInsecure {
		return fmt.Errorf(
			"calico provider does not support TLS mode %q; use existingSecret or issuer",
			tlsMode,
		)
	}
	return nil
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
		factory, err := newAgentClientFactory(conf)
		if err != nil {
			return err
		}
		istioScraper := scraper.NewIstioScraper(scraper.IstioScraperConfig{
			ViolationBuffer:      violationBuffer,
			EnqueueLearningEvent: learningEnqueueFunc,
			ViolationOtelLogger:  eventLogger,
			Logger:               logger.With("component", "istio-scraper"),
			Enricher:             istio.NewEnricher(mgr.GetClient()),
			FlowDumperBuffer:     flowDumperBuffer,
		})
		istioScraper.ConfigurePulling(scraper.IstioPullConfig{
			Cache:  mgr.GetCache(),
			Reader: mgr.GetCache(),
			DialAgent: func(ctx context.Context, endpoint, authority string) (grpcexporter.AgentClientAPI, error) {
				return factory.Dial(ctx, endpoint, authority)
			},
			Namespace:     conf.agent.namespace,
			LabelSelector: conf.agent.labelSelector,
			GRPCPort:      conf.agent.grpcPort,
			PollInterval:  conf.agent.pollInterval,
			ScrapeTimeout: conf.agent.scrapeTimeout,
			MaxInFlight:   conf.agent.maxInFlight,
		})
		if err = mgr.Add(istioScraper); err != nil {
			return fmt.Errorf("unable to add istio scraper to manager: %w", err)
		}
		return nil
	case types.ProviderCilium:
		certSource, err := newProviderCertSource(mgr, conf)
		if err != nil {
			return err
		}
		ciliumScraper := scraper.NewCiliumScraper(scraper.CiliumScraperConfig{
			Client:               mgr.GetClient(),
			Logger:               logger.With("component", "cilium-scraper"),
			Endpoint:             conf.provider.endpoint,
			EnqueueLearningEvent: learningEnqueueFunc,
			ViolationOtelLogger:  eventLogger,
			ViolationBuffer:      violationBuffer,
			FlowDumperBuffer:     flowDumperBuffer,
			CertSource:           certSource,
			TLSServerName:        conf.provider.tlsServerName,
		})
		if err = mgr.Add(ciliumScraper); err != nil {
			return fmt.Errorf("unable to add cilium scraper to manager: %w", err)
		}
		return nil
	case types.ProviderCalico:
		if err := validateCalicoTLSMode(conf.provider.tlsMode); err != nil {
			return err
		}
		certSource, err := newProviderCertSource(mgr, conf)
		if err != nil {
			return err
		}
		calicoScraper := scraper.NewCalicoScraper(scraper.CalicoScraperConfig{
			Client:               mgr.GetClient(),
			Endpoint:             conf.provider.endpoint,
			EnqueueLearningEvent: learningEnqueueFunc,
			Logger:               logger.With("component", "calico-scraper"),
			ViolationOtelLogger:  eventLogger,
			ViolationBuffer:      violationBuffer,
			FlowDumperBuffer:     flowDumperBuffer,
			CertSource:           certSource,
			TLSServerName:        conf.provider.tlsServerName,
		})
		if err = mgr.Add(calicoScraper); err != nil {
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
		WebhookServer:          webhook.NewServer(webhook.Options{TLSOpts: conf.tlsOpts}),
		HealthProbeBindAddress: conf.probeAddr,
		LeaderElection:         conf.enableLeaderElection,
		LeaderElectionID:       "6163c1ee.networkenforcer.kubewarden.io",
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
	otelCfg otelConf,
) (otellog.Logger, error) {
	if err := otlp.ValidateEndpoint(otelCfg.Endpoint); err != nil {
		return nil, err
	}
	eventLogger, eventShutdown, err := events.Init(ctx, otelCfg.Protocol)
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

func validateProviderConfiguration(logger *slog.Logger, conf *config) error {
	if types.Provider(conf.provider.name) != types.ProviderIstio {
		if err := certsource.Validate(conf.provider.certSourceConfig()); err != nil {
			return fmt.Errorf("invalid provider TLS flags: %w", err)
		}
		return nil
	}
	if err := scraper.ValidateIstioPullOptions(
		conf.agent.namespace,
		conf.agent.labelSelector,
		conf.agent.grpcPort,
		conf.agent.pollInterval,
		conf.agent.scrapeTimeout,
		conf.agent.maxInFlight,
	); err != nil {
		return err
	}
	if conf.agent.maxRecvMsgSize <= 0 {
		return errors.New("--agent-grpc-max-recv-msg-size must be positive")
	}
	for _, name := range conf.legacyIstioFlags {
		logger.Warn("Istio provider flag is deprecated and ignored; use the agent pull settings", "flag", "--"+name)
	}
	return nil
}

func run(logger *slog.Logger, conf *config) error {
	if err := validateProviderConfiguration(logger, conf); err != nil {
		return err
	}

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

	// Violations are correlated to their WNP by (targetRef, direction).
	if err = controller.SetupWNPIndexer(ctx, mgr); err != nil {
		return fmt.Errorf("unable to set up WorkloadNetworkPolicy target indexer: %w", err)
	}

	var eventLogger otellog.Logger
	if conf.otel.Endpoint != "" {
		eventLogger, err = setupOtelLogExporter(ctx, logger, mgr, conf.otel)
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

	learningReconciler := controller.NewLearningReconciler(
		mgr.GetClient(),
		mgr.GetScheme(),
		violationBuffer,
		eventLogger,
	)
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

	if err = setupHealthChecks(mgr); err != nil {
		return err
	}

	logger.InfoContext(ctx, "starting manager")
	return mgr.Start(ctx)
}

func setupHealthChecks(mgr manager.Manager) error {
	cacheSynced := &atomic.Bool{}
	if err := mgr.Add(cacheSyncReadinessRunnable{cache: mgr.GetCache(), synced: cacheSynced}); err != nil {
		return fmt.Errorf("unable to add cache sync readiness runnable: %w", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to add healthz check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to add readyz check: %w", err)
	}
	if err := mgr.AddReadyzCheck("webhook", mgr.GetWebhookServer().StartedChecker()); err != nil {
		return fmt.Errorf("unable to add webhook readyz check: %w", err)
	}
	if err := mgr.AddReadyzCheck("cache", func(_ *http.Request) error {
		if !cacheSynced.Load() {
			return errors.New("manager cache has not synchronized")
		}
		return nil
	}); err != nil {
		return fmt.Errorf("unable to add cache readyz check: %w", err)
	}
	return nil
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
	conf.wnpStatusSyncConfig.MetricsRegisterer = ctrlmetrics.Registry
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

	err = builder.WebhookManagedBy(mgr, &securityv1alpha1.WorkloadNetworkPolicy{}).
		WithValidator(&controller.PolicyValidator{Client: mgr.GetClient()}).
		Complete()
	if err != nil {
		return fmt.Errorf("unable to create WorkloadNetworkPolicy webhook: %w", err)
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
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
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
	flag.StringVar(&conf.provider.tlsMode, "provider-tls-mode", string(certsource.ModeInsecure),
		"TLS mode for the provider hop: issuer, existingSecret, or insecure.")
	flag.StringVar(&conf.provider.tlsCertDir, "provider-tls-cert-dir", "",
		"Directory containing tls.crt, tls.key, and ca.crt for the provider hop. "+
			"Used with --provider-tls-mode=issuer or a mounted existingSecret.")
	flag.StringVar(&conf.provider.tlsCertSecret, "provider-tls-cert-secret", "",
		"Secret holding provider TLS material, as namespace/name. "+
			"Used with --provider-tls-mode=existingSecret.")
	flag.StringVar(&conf.provider.tlsCAConfigMap, "provider-tls-ca-configmap", "",
		"Optional ConfigMap holding the provider CA bundle, as namespace/name. "+
			"Used with --provider-tls-cert-secret.")
	flag.StringVar(&conf.provider.tlsCABundleKey, "provider-tls-ca-bundle-key", "",
		"ConfigMap data key for the provider CA bundle when --provider-tls-ca-configmap is set. "+
			"Defaults to ca.crt.")
	flag.StringVar(&conf.provider.tlsServerName, "provider-tls-server-name", "",
		"Optional TLS server name verified against the provider's server certificate. "+
			"Defaults to the host part of --provider-endpoint.")
	flag.BoolVar(&conf.agent.mtlsEnabled, "agent-grpc-mtls-enabled", false,
		"Enable mutual TLS when the controller dials the agent gRPC server.")
	flag.StringVar(&conf.agent.certDirPath, "agent-grpc-mtls-cert-dir", "",
		"Directory holding tls.crt, tls.key, and ca.crt for the agent hop client. "+
			"Required when --agent-grpc-mtls-enabled is set.")
	flag.StringVar(&conf.agent.namespace, "agent-namespace", "",
		"Required namespace for Istio agent Pod discovery.")
	flag.StringVar(&conf.agent.labelSelector, "agent-label-selector",
		scraper.DefaultAgentLabelSelector,
		"Label selector used to discover Istio agent Pods.")
	flag.IntVar(&conf.agent.grpcPort, "agent-grpc-port", scraper.DefaultAgentGRPCPort,
		"TCP port the Istio agent gRPC server listens on.")
	flag.DurationVar(&conf.agent.pollInterval, "agent-poll-interval", scraper.DefaultAgentPollInterval,
		"Successful Istio agent scrape interval; permit wait, scrape, and processing add to the effective interval.")
	flag.DurationVar(&conf.agent.scrapeTimeout, "agent-scrape-timeout", scraper.DefaultAgentScrapeTimeout,
		"Timeout for one Istio agent scrape RPC.")
	flag.IntVar(&conf.agent.maxInFlight, "agent-max-in-flight", scraper.DefaultAgentMaxInFlight,
		"Maximum concurrent agent scrapes and event processing across all discovered Istio agents.")
	flag.IntVar(&conf.agent.maxRecvMsgSize, "agent-grpc-max-recv-msg-size", grpcexporter.DefaultAgentMaxRecvMsgSize,
		"Maximum size in bytes of one agent gRPC response; oversized drained responses are lost.")
	flag.DurationVar(&conf.wnpStatusSyncConfig.UpdateInterval,
		"wnp-status-reconciler-update-interval",
		defaultWnpStatusUpdateInterval,
		"The interval at which WorkloadNetworkPolicy status is synced.")
	flag.Parse()
	conf.legacyIstioFlags = explicitlySetProviderFlags(flag.CommandLine)
	// The OpenTelemetry SDK reads the other OTEL_EXPORTER_OTLP_* variables itself.
	conf.otel.Endpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	conf.otel.Protocol = os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")

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
