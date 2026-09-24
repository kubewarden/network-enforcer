package e2e_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

const (
	calicoSystemNamespace = "calico-system"
	goldmaneWaitTimeout   = 5 * time.Minute
	calicoHelmTimeout     = 10 * time.Minute
)

func waitGoldmaneDeployment(ctx context.Context, calicoNamespace string) error {
	const goldmaneDeployment = "goldmane"
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	r := getSecurityV1Alpha1Client(ctx)
	logger.InfoContext(ctx, "⏲️ waiting for goldmane deployment to be ready")

	// DeploymentAvailable will return an error if the deployment is not found,
	// so wait for the object to exist first.
	if err := wait.For(
		conditions.New(r).ResourceMatch(&appsv1.Deployment{
			Name:      goldmaneDeployment,
			Namespace: calicoNamespace,
		}, func(_ k8s.Object) bool { return true }),
		wait.WithTimeout(goldmaneWaitTimeout),
	); err != nil {
		return fmt.Errorf("goldmane deployment not found: %w", err)
	}
	return wait.For(
		conditions.New(r).DeploymentAvailable(goldmaneDeployment, calicoNamespace),
		wait.WithTimeout(goldmaneWaitTimeout),
	)
}

func waitGoldmaneConfigMap(ctx context.Context, calicoNamespace string) error {
	const goldmaneConfigMapName = "goldmane-ca-bundle"
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	r := getSecurityV1Alpha1Client(ctx)

	logger.InfoContext(ctx, "⏲️ waiting for Goldmane CA bundle configmap")
	caBundleCM := &corev1.ConfigMap{
		Name:      goldmaneConfigMapName,
		Namespace: calicoNamespace,
	}
	if err := wait.For(
		conditions.New(r).ResourceMatch(caBundleCM, func(_ k8s.Object) bool { return true }),
		wait.WithTimeout(defaultOperationTimeout),
	); err != nil {
		return fmt.Errorf("wait goldmane CA bundle configmap: %w", err)
	}
	return nil
}

func waitGoldmaneSecret(ctx context.Context, calicoNamespace string) error {
	const goldmaneSecretName = "goldmane-key-pair"
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	r := getSecurityV1Alpha1Client(ctx)

	logger.InfoContext(ctx, "⏲️ waiting for Goldmane secret")
	goldmaneSecret := &corev1.Secret{
		Name:      goldmaneSecretName,
		Namespace: calicoNamespace,
	}
	if err := wait.For(
		conditions.New(r).ResourceMatch(goldmaneSecret, func(_ k8s.Object) bool { return true }),
		wait.WithTimeout(defaultOperationTimeout),
	); err != nil {
		return fmt.Errorf("wait goldmane key pair secret: %w", err)
	}
	return nil
}

func installCalicoCRDs(ctx context.Context, manager *helm.Manager, repoLocalName, version string) error {
	const (
		releaseName  = "calico-crds"
		crdChartPath = "/crd.projectcalico.org.v1"
	)

	logger := getSetupLogger(ctx)
	logger.InfoContext(ctx, "🛠️ installing calico CRDs", "chart", repoLocalName+crdChartPath, "version", version)

	helmOpts := []helm.Option{
		helm.WithName(releaseName),
		helm.WithChart(repoLocalName + crdChartPath),
		helm.WithVersion(version),
		helm.WithArgs("--install"),
		helm.WithWait(),
		helm.WithTimeout(calicoHelmTimeout.String()),
	}

	if err := manager.RunUpgrade(helmOpts...); err != nil {
		return fmt.Errorf("install calico CRDs chart: %w", err)
	}

	return nil
}

func installCalico(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
	const (
		releaseName      = "tigera-operator"
		releaseNamespace = "tigera-operator"
		defaultVersion   = "v3.32.1"
		repoLocalName    = defaultNamespacePref + "-calico"
		repoURL          = "https://docs.tigera.io/calico/charts"
		chartPath        = "/tigera-operator"
	)

	manager := helm.New(cfg.KubeconfigFile())

	if err := addLocalChartRepo(ctx, manager, repoLocalName, repoURL); err != nil {
		return ctx, fmt.Errorf("add local chart repo: %w", err)
	}

	version := getCNIVersion(ctx, defaultVersion)
	if err := installCalicoCRDs(ctx, manager, repoLocalName, version); err != nil {
		return ctx, err
	}

	logger := getSetupLogger(ctx)

	helmOpts := []helm.Option{
		helm.WithName(releaseName),
		helm.WithNamespace(releaseNamespace),
		helm.WithChart(repoLocalName + chartPath),
		helm.WithVersion(version),
		helm.WithArgs("--create-namespace"),
		helm.WithArgs("--set", "installation.enabled=true"),
		helm.WithArgs("--set", "apiServer.enabled=true"),
		helm.WithArgs("--set", "goldmane.enabled=true"),
		helm.WithArgs("--set", "whisker.enabled=false"),
		helm.WithArgs("--set", "installation.calicoNetwork.ipPools[0].name=default-ipv4-ippool"),
		// As a dataplane for now we use the default one: Iptables # https://github.com/projectcalico/calico/blob/58949447b523cd9ed372c7cbcf3601c027fa80d8/charts/tigera-operator/values.yaml#L48
		helm.WithArgs("--set", "installation.calicoNetwork.linuxDataplane=Iptables"),
		// `10.244.0.0/16` is the default Kind Cluster CIDR
		helm.WithArgs("--set", "installation.calicoNetwork.ipPools[0].cidr=10.244.0.0/16"),
		// To enable trace logs in calico:
		// helm.WithArgs("--set", "defaultFelixConfiguration.enabled=true"),
		// helm.WithArgs("--set", "defaultFelixConfiguration.logSeverityScreen=Trace"),
		helm.WithWait(),
		helm.WithTimeout(calicoHelmTimeout.String()),
	}

	logger.InfoContext(
		ctx,
		"🛠️ installing tigera operator",
		"chart",
		repoLocalName+chartPath,
		"version",
		version,
	)
	if err := manager.RunInstall(helmOpts...); err != nil {
		return ctx, fmt.Errorf("install tigera operator chart: %w", err)
	}

	if err := waitGoldmaneDeployment(ctx, calicoSystemNamespace); err != nil {
		return ctx, err
	}

	// Wait for operator-managed TLS material the chart reads over the API.
	if err := waitGoldmaneConfigMap(ctx, calicoSystemNamespace); err != nil {
		return ctx, err
	}
	if err := waitGoldmaneSecret(ctx, calicoSystemNamespace); err != nil {
		return ctx, err
	}

	return ctx, nil
}
