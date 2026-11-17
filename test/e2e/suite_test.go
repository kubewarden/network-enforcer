package e2e_test

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/e2e-framework/klient/conf"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/support/kind"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

const (
	// The chart does not deploy a collector.
	// The suite applies this manifest before it installs the chart.
	// It is not in testdata, because some tests apply every file in testdata.
	otelCollectorManifestDir    = "./manifests"
	otelCollectorManifest       = "otel-collector.yaml"
	otelCollectorDeploymentName = "otel-collector"
	otelCollectorReadyWait      = 3 * time.Minute
)

// otelCollectorEndpoint is the plaintext gRPC endpoint of the e2e collector.
// The http:// scheme turns off TLS in the exporter.
func otelCollectorEndpoint(namespace string) string {
	return fmt.Sprintf("http://%s.%s.svc.cluster.local:4317", otelCollectorDeploymentName, namespace)
}

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
		imageLoads := []env.Func{
			envfuncs.CreateClusterWithConfig(kind.NewProvider(), clusterName, testSuiteConf.kindConfigPath),
			envfuncs.LoadImageToCluster(clusterName, testSuiteConf.controllerImage),
		}
		if testSuiteConf.IsIstioProvider() {
			imageLoads = append(imageLoads, envfuncs.LoadImageToCluster(clusterName, testSuiteConf.agentImage))
		}
		setupFuncs = append(imageLoads, setupFuncs...)
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
		// The collector must be ready before the network enforcer starts,
		// so that the exporter sees no connection errors at startup.
		// The suite never uninstalls the chart, so it does not delete the collector either.
		setupFuncs = append(setupFuncs, setupOtelCollector(), installNetEnforcerChart())
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
		helmOpts := netEnforcerHelmOpts(testCfg)

		logger.InfoContext(ctx, "🛠️ installing network enforcer chart", "releaseName", testCfg.releaseName)
		if err := manager.RunInstall(helmOpts...); err != nil {
			return ctx, fmt.Errorf("install network enforcer chart: %w", err)
		}

		r, err := resources.New(cfg.Client().RESTConfig())
		if err != nil {
			return ctx, fmt.Errorf("create resources client: %w", err)
		}
		if err = waitForNetEnforcerReady(ctx, logger, r, testCfg); err != nil {
			return ctx, err
		}
		return ctx, nil
	}
}

func netEnforcerHelmOpts(testCfg suiteConfig) []helm.Option {
	controllerRepo, controllerTag := parseImage(testCfg.controllerImage)
	helmOpts := []helm.Option{
		helm.WithName(testCfg.releaseName),
		helm.WithNamespace(testCfg.releaseNS),
		helm.WithChart(testCfg.chartPath),
		helm.WithArgs("--create-namespace"),
		// The e2e image is a full reference with the registry,
		// so the chart must not add its own registry.
		helm.WithArgs("--set", "controller.image.registry="),
		helm.WithArgs("--set", fmt.Sprintf("controller.image.repository=%s", controllerRepo)),
		helm.WithArgs("--set", fmt.Sprintf("controller.image.tag=%s", controllerTag)),
		helm.WithArgs("--set", "controller.logLevel=debug"),
		helm.WithArgs("--set", "controller.flowDumper.enabled=true"),
		helm.WithArgs("--set", fmt.Sprintf("controller.provider.name=%s", testCfg.ProviderName())),
		helm.WithArgs("--set", fmt.Sprintf("controller.wnpStatusUpdateInterval=%s",
			testCfg.wnpStatusUpdateInterval.String())),
		// The suite deploys this collector before it installs the chart.
		helm.WithArgs("--set", "global.otel.endpoint="+otelCollectorEndpoint(testCfg.releaseNS)),
		helm.WithWait(),
		helm.WithTimeout(defaultHelmTimeout.String()),
	}
	if testCfg.HasE2EDependency("cert-manager") && testCfg.IsIstioProvider() {
		helmOpts = append(helmOpts, helm.WithArgs("--set", "controller.provider.istio.tls.mode=issuer"))
	}
	if testCfg.IsIstioProvider() {
		agentRepo, agentTag := parseImage(testCfg.agentImage)
		helmOpts = append(helmOpts,
			helm.WithArgs("--set", "controller.provider.istio.agent.image.registry="),
			helm.WithArgs("--set", fmt.Sprintf("controller.provider.istio.agent.image.repository=%s", agentRepo)),
			helm.WithArgs("--set", fmt.Sprintf("controller.provider.istio.agent.image.tag=%s", agentTag)),
		)
	}
	return helmOpts
}

func waitForNetEnforcerReady(
	ctx context.Context,
	logger *slog.Logger,
	r *resources.Resources,
	testCfg suiteConfig,
) error {
	logger.InfoContext(ctx, "⏲️ waiting for network enforcer controller")
	if err := wait.For(
		conditions.New(r).DeploymentAvailable("network-enforcer-controller-manager", testCfg.releaseNS),
		wait.WithTimeout(defaultOperationTimeout),
	); err != nil {
		return fmt.Errorf("wait network enforcer deployment ready: %w", err)
	}

	logger.InfoContext(ctx, "⏲️ waiting for the admission webhook CA bundle")
	if err := wait.For(
		conditions.New(r).ResourceMatch(
			&admissionregistrationv1.ValidatingWebhookConfiguration{
				Name: wnpValidatingWebhookConfigurationName,
			},
			func(obj k8s.Object) bool {
				vwc, ok := obj.(*admissionregistrationv1.ValidatingWebhookConfiguration)
				return ok && len(vwc.Webhooks) > 0 && len(vwc.Webhooks[0].ClientConfig.CABundle) > 0
			}),
		wait.WithTimeout(defaultOperationTimeout),
	); err != nil {
		return fmt.Errorf("wait admission webhook CA bundle injected: %w", err)
	}

	if testCfg.IsIstioProvider() {
		logger.InfoContext(ctx, "⏲️ waiting for Istio agent")
		if err := wait.For(
			conditions.New(r).DaemonSetReady(
				&appsv1.DaemonSet{
					Name:      testCfg.releaseName + "-agent",
					Namespace: testCfg.releaseNS,
				}),
			wait.WithTimeout(defaultOperationTimeout),
		); err != nil {
			return fmt.Errorf("wait Istio agent daemonset ready: %w", err)
		}
		if err := assertIstioAgentInstallation(ctx, r, testCfg); err != nil {
			return err
		}
	}
	return nil
}

func assertIstioAgentInstallation(ctx context.Context, r *resources.Resources, testCfg suiteConfig) error {
	namespace := testCfg.releaseNS
	var agent appsv1.DaemonSet
	if err := r.Get(ctx, testCfg.releaseName+"-agent", namespace, &agent); err != nil {
		return fmt.Errorf("get Istio agent DaemonSet: %w", err)
	}
	var ztunnel appsv1.DaemonSet
	if err := r.Get(ctx, "ztunnel", istioNamespace, &ztunnel); err != nil {
		return fmt.Errorf("get ztunnel DaemonSet: %w", err)
	}
	if agent.Status.NumberReady != ztunnel.Status.NumberReady {
		return fmt.Errorf(
			"agent has %d ready pods for %d ready ztunnel pods",
			agent.Status.NumberReady,
			ztunnel.Status.NumberReady,
		)
	}
	if err := assertIstioAgentPod(agent.Spec.Template.Spec, testCfg.releaseName); err != nil {
		return err
	}
	var serviceAccount corev1.ServiceAccount
	if err := r.Get(ctx, testCfg.releaseName+"-agent", namespace, &serviceAccount); err != nil {
		return fmt.Errorf("get Istio agent ServiceAccount: %w", err)
	}
	if serviceAccount.AutomountServiceAccountToken == nil || *serviceAccount.AutomountServiceAccountToken {
		return errors.New("agent ServiceAccount must disable token automount")
	}
	return assertFluentBitResources(ctx, r, namespace, testCfg.releaseName)
}

func assertIstioAgentPod(podSpec corev1.PodSpec, releaseName string) error {
	if podSpec.ServiceAccountName != releaseName+"-agent" || podSpec.AutomountServiceAccountToken == nil ||
		*podSpec.AutomountServiceAccountToken {
		return errors.New("agent pod must use its tokenless dedicated ServiceAccount")
	}
	if podSpec.SecurityContext == nil || podSpec.SecurityContext.RunAsNonRoot == nil ||
		*podSpec.SecurityContext.RunAsNonRoot {
		return errors.New("agent pod must allow the root UID needed to read kubelet logs")
	}
	container := findContainer(podSpec.Containers, "agent")
	if container == nil || container.SecurityContext == nil || container.SecurityContext.RunAsUser == nil ||
		*container.SecurityContext.RunAsUser != 0 ||
		container.SecurityContext.ReadOnlyRootFilesystem == nil ||
		!*container.SecurityContext.ReadOnlyRootFilesystem {
		return errors.New("agent container must run as root with a read-only root filesystem")
	}
	if container.SecurityContext.AllowPrivilegeEscalation == nil ||
		*container.SecurityContext.AllowPrivilegeEscalation {
		return errors.New("agent container must disable privilege escalation")
	}
	return assertIstioAgentLogMounts(container.VolumeMounts)
}

func findContainer(containers []corev1.Container, name string) *corev1.Container {
	for i := range containers {
		if containers[i].Name == name {
			return &containers[i]
		}
	}
	return nil
}

func assertIstioAgentLogMounts(mounts []corev1.VolumeMount) error {
	for _, required := range []struct{ name, path string }{{"varlog-pods", "/var/log/pods"}, {"varlog-containers", "/var/log/containers"}} {
		found := false
		for _, mount := range mounts {
			if mount.Name == required.name && mount.MountPath == required.path && mount.ReadOnly {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("agent is missing read-only mount %s", required.path)
		}
	}
	return nil
}

func assertFluentBitResources(ctx context.Context, r *resources.Resources, namespace, releaseName string) error {
	var config corev1.ConfigMap
	if err := r.Get(ctx, releaseName+"-istio-fluent-bit", namespace, &config); err != nil {
		return fmt.Errorf("get retained Istio Fluent Bit ConfigMap: %w", err)
	}
	var daemonSet appsv1.DaemonSet
	if err := r.Get(ctx, releaseName+"-istio-fluent-bit", namespace, &daemonSet); err != nil {
		return fmt.Errorf("get retained Istio Fluent Bit DaemonSet: %w", err)
	}
	var account corev1.ServiceAccount
	if err := r.Get(ctx, releaseName+"-istio-fluent-bit", namespace, &account); err != nil {
		return fmt.Errorf("get retained Istio Fluent Bit ServiceAccount: %w", err)
	}
	return nil
}

func parseImage(image string) (string, string) {
	if i := strings.LastIndex(image, ":"); i > 0 && i > strings.LastIndex(image, "/") {
		return image[:i], image[i+1:]
	}
	return image, "latest"
}

// setupOtelCollector deploys the collector in the release namespace
// and waits until its Deployment is available.
// It first deletes a collector left by an earlier run,
// so that a reused cluster also gets the current manifest.
// The new Deployment counts only its own pods,
// so an old pod that is still shutting down cannot make it available.
func setupOtelCollector() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
		namespace := getSuiteConfig(ctx).releaseNS

		client, err := cfg.NewClient()
		if err != nil {
			return ctx, fmt.Errorf("failed to create the client: %w", err)
		}
		r := client.Resources(namespace)

		ns := &corev1.Namespace{Name: namespace}
		if err = r.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
			return ctx, fmt.Errorf("failed to create namespace %s: %w", namespace, err)
		}

		manifests := os.DirFS(otelCollectorManifestDir)
		err = decoder.DecodeEachFile(ctx, manifests, otelCollectorManifest,
			decoder.DeleteIgnoreNotFound(r), decoder.MutateNamespace(namespace))
		if err != nil {
			return ctx, fmt.Errorf("failed to delete the old otel collector: %w", err)
		}

		logger.InfoContext(ctx, "deploying otel collector", "namespace", namespace)
		err = decoder.DecodeEachFile(ctx, manifests, otelCollectorManifest,
			decoder.CreateHandler(r), decoder.MutateNamespace(namespace))
		if err != nil {
			return ctx, fmt.Errorf("failed to create the otel collector: %w", err)
		}

		err = wait.For(
			conditions.New(r).DeploymentAvailable(otelCollectorDeploymentName, namespace),
			wait.WithContext(ctx),
			wait.WithTimeout(otelCollectorReadyWait),
		)
		if err != nil {
			return ctx, fmt.Errorf("otel collector is not available: %w", err)
		}
		logger.InfoContext(ctx, "otel collector ready", "namespace", namespace)
		return ctx, nil
	}
}
