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
	goldmaneClientSecret  = "net-enf-goldmane-client-certs"
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

func waitGoldmaneConfigMap(ctx context.Context, calicoNamespace string) (*corev1.ConfigMap, error) {
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
		return nil, fmt.Errorf("wait goldmane CA bundle configmap: %w", err)
	}
	return caBundleCM, nil
}

func waitGoldmaneSecret(ctx context.Context, calicoNamespace string) (*corev1.Secret, error) {
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
		return nil, fmt.Errorf("wait goldmane key pair secret: %w", err)
	}

	return goldmaneSecret, nil
}

func generateGoldmaneClientSecret(ctx context.Context, configMap *corev1.ConfigMap, secret *corev1.Secret) error {
	const (
		tigeraCABundleKey = "tigera-ca-bundle.crt"
		tlsCrtKey         = "tls.crt"
		tlsKey            = "tls.key"
		caBundleKey       = "ca.crt"
	)

	caBundle, ok := configMap.Data[tigeraCABundleKey]
	if !ok {
		return fmt.Errorf("missing key %q in configmap %q", tigeraCABundleKey, configMap.Name)
	}
	crt, ok := secret.Data[tlsCrtKey]
	if !ok {
		return fmt.Errorf("missing key %q in secret %q", tlsCrtKey, secret.Name)
	}
	key, ok := secret.Data[tlsKey]
	if !ok {
		return fmt.Errorf("missing key %q in secret %q", tlsKey, secret.Name)
	}

	clientSecret := &corev1.Secret{
		Name:      goldmaneClientSecret,
		Namespace: getSuiteConfig(ctx).releaseNS,
		Type:      corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			caBundleKey: []byte(caBundle),
			tlsCrtKey:   crt,
			tlsKey:      key,
		},
	}

	if err := getSecurityV1Alpha1Client(ctx).Create(ctx, clientSecret); err != nil {
		return fmt.Errorf("cannot create Goldmane client secret: %w", err)
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

	goldmaneConfigMap, err := waitGoldmaneConfigMap(ctx, calicoSystemNamespace)
	if err != nil {
		return ctx, err
	}

	goldmaneSecret, err := waitGoldmaneSecret(ctx, calicoSystemNamespace)
	if err != nil {
		return ctx, err
	}

	r := getSecurityV1Alpha1Client(ctx)
	netEnforcerReleaseNs := getSuiteConfig(ctx).releaseNS
	logger.InfoContext(ctx, "🛠️ create", "namespace", netEnforcerReleaseNs)
	if err = r.Create(ctx, &corev1.Namespace{
		Name: netEnforcerReleaseNs}); err != nil {
		return ctx, fmt.Errorf("create %s namespace: %w", netEnforcerReleaseNs, err)
	}

	return ctx, generateGoldmaneClientSecret(ctx, goldmaneConfigMap, goldmaneSecret)
}
