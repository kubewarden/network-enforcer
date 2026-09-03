package e2e_test

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/e2e-framework/klient/conf"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/support/kind"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

var (
	testEnv env.Environment //nolint:gochecknoglobals // provided by e2e-framework
)

func TestMain(m *testing.M) {
	testSuiteConf := loadSuiteConfig()

	path := conf.ResolveKubeConfigFile()
	// WithFailFast allows us to skip the teardown phase in case of test failures
	// https://github.com/kubernetes-sigs/e2e-framework/blob/1cdb40b1d89482bc7ce0e7ab2e530d2426a7ea91/pkg/env/env.go#L538
	cfg := envconf.NewWithKubeConfig(path).WithFailFast()
	testEnv = env.NewWithConfig(cfg)

	var suiteFailed atomic.Bool
	// we initially set it to true so that if we fail during setup, we can skip teardown
	suiteFailed.Store(true)
	testEnv.AfterEachTest(func(ctx context.Context, _ *envconf.Config, t *testing.T) (context.Context, error) {
		if t.Failed() {
			suiteFailed.Store(true)
		} else {
			suiteFailed.Store(false)
		}
		return ctx, nil
	})

	clusterName := envconf.RandomName(testSuiteConf.namespacePrefix, 20)
	if testSuiteConf.installClusterOnly != "" {
		clusterName = testSuiteConf.installClusterOnly
		// We use '^$' to run tests so that we are sure nothing will run.
		_ = flag.Set("test.run", "^$")
	}

	// Base setup — always runs.
	// we inject the suite config in the context so that each test can access parameters like the release name, namespace, image, etc.
	setupFuncs := []env.Func{
		injectSuiteConfig(testSuiteConf),
		injectSetupLogger(),
		injectSecurityV1Alpha1Client(),
	}
	finishFuncs := []env.Func{}

	// Cluster creation + image loading — skipped when reusing an existing cluster.
	if !testSuiteConf.useExistingCluster {
		setupFuncs = append([]env.Func{
			envfuncs.CreateClusterWithConfig(kind.NewProvider(), clusterName, testSuiteConf.kindConfigPath),
			envfuncs.LoadImageToCluster(clusterName, testSuiteConf.controllerImage),
		}, setupFuncs...)
	}

	// Optional dependencies, controlled by E2E_DEPENDENCIES.
	// Default (empty/unset): both are installed. Set "none" to skip all.
	if testSuiteConf.HasE2EDependency("provider") {
		setupFuncs = append(setupFuncs, installProvider())
	}

	if testSuiteConf.HasE2EDependency("cert-manager") {
		setupFuncs = append(setupFuncs, installCertManager())
	}

	if testSuiteConf.installClusterOnly == "" {
		// We install the network-enforcer and we destroy the cluster only in case we are running tests.
		setupFuncs = append(setupFuncs, installNetEnforcerChart())
		if !testSuiteConf.useExistingCluster {
			finishFuncs = append(finishFuncs,
				envfuncs.ExportClusterLogs(clusterName, testSuiteConf.logsDir),
				func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
					if suiteFailed.Load() {
						getSetupLogger(ctx).InfoContext(
							ctx,
							"⏩ Skipping cluster destroy to debug",
							"clusterName", clusterName,
						)
						return ctx, nil
					}
					return envfuncs.DestroyCluster(clusterName)(ctx, cfg)
				},
			)
		}
	}

	testEnv.Setup(setupFuncs...)
	testEnv.Finish(finishFuncs...)
	os.Exit(testEnv.Run(m))
}

func installNetEnforcerChart() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
		manager := helm.New(cfg.KubeconfigFile())

		testCfg := getSuiteConfig(ctx)
		controllerRepo, controllerTag := parseImage(testCfg.controllerImage)

		helmOpts := []helm.Option{
			helm.WithName(testCfg.releaseName),
			helm.WithNamespace(testCfg.releaseNS),
			helm.WithChart(testCfg.chartPath),
			helm.WithArgs("--create-namespace"),
			helm.WithArgs("--set", fmt.Sprintf("controller.image.repository=%s", controllerRepo)),
			helm.WithArgs("--set", fmt.Sprintf("controller.image.tag=%s", controllerTag)),
			helm.WithArgs("--set", "controller.logLevel=debug"),
			helm.WithArgs("--set", "controller.flowDumper.enabled=true"),
			helm.WithArgs("--set", fmt.Sprintf("controller.provider.name=%s", testCfg.ProviderName())),
			helm.WithArgs("--set", fmt.Sprintf("controller.wnpStatusUpdateInterval=%s",
				testCfg.wnpStatusUpdateInterval.String())),
			helm.WithWait(),
			helm.WithTimeout(defaultHelmTimeout.String()),
		}
		if !testCfg.HasE2EDependency("cert-manager") {
			helmOpts = append(helmOpts, helm.WithArgs("--set", "telemetry.collectorStrategy=none"))
		}

		logger.InfoContext(ctx, "🛠️ installing network enforcer chart", "releaseName", testCfg.releaseName)
		if err := manager.RunInstall(helmOpts...); err != nil {
			return ctx, fmt.Errorf("install network enforcer chart: %w", err)
		}

		r, err := resources.New(cfg.Client().RESTConfig())
		if err != nil {
			return ctx, fmt.Errorf("create resources client: %w", err)
		}

		logger.InfoContext(ctx, "⏲️ waiting for network enforcer controller")
		if err = wait.For(
			conditions.New(r).DeploymentAvailable("network-enforcer-controller-manager", testCfg.releaseNS),
			wait.WithTimeout(defaultOperationTimeout),
		); err != nil {
			return ctx, fmt.Errorf("wait network enforcer deployment ready: %w", err)
		}

		if testCfg.HasE2EDependency("cert-manager") {
			logger.InfoContext(ctx, "⏲️ waiting for default otel collector")
			if err = wait.For(
				conditions.New(r).DeploymentAvailable("network-enforcer-otel-collector", testCfg.releaseNS),
				wait.WithTimeout(defaultOperationTimeout),
			); err != nil {
				return ctx, fmt.Errorf("wait default otel collector deployment ready: %w", err)
			}
		}

		if testCfg.IsIstioProvider() {
			// the istio-fluent-bit DaemonSet tails ztunnel access logs and forwards
			// them via OTLP to the controller's istio scraper (the learning source).
			logger.InfoContext(ctx, "⏲️ waiting for istio fluent-bit")
			if err = wait.For(
				conditions.New(r).DaemonSetReady(
					&appsv1.DaemonSet{
						Name:      "network-enforcer-istio-fluent-bit",
						Namespace: testCfg.releaseNS,
					}),
				wait.WithTimeout(defaultOperationTimeout),
			); err != nil {
				return ctx, fmt.Errorf("wait istio fluent-bit daemonset ready: %w", err)
			}
		}

		return ctx, nil
	}
}

func parseImage(image string) (string, string) {
	if i := strings.LastIndex(image, ":"); i > 0 && i > strings.LastIndex(image, "/") {
		return image[:i], image[i+1:]
	}
	return image, "latest"
}
