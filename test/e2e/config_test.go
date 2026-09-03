package e2e_test

import (
	"context"
	"os"
	"slices"
	"strings"
	"time"

	netypes "github.com/kubewarden/network-enforcer/internal/types"
)

const (
	defaultChartPath               = "../../charts/network-enforcer"
	defaultLogsDir                 = "./logs"
	defaultControllerImage         = "ghcr.io/kubewarden/network-enforcer/controller:latest"
	defaultReleaseName             = "network-enforcer"
	defaultReleaseNS               = "network-enforcer"
	defaultNamespacePref           = "network-enforcer-e2e"
	defaultKindConfigIstioPath     = "./clusters/istio.yaml"
	defaultKindConfigNoCNIPath     = "./clusters/no-cni.yaml"
	defaultWnpStatusUpdateInterval = 3 * time.Second // we reduce the time here to have faster feedback from the controller
)

const (
	defaultHelmTimeout      = 3 * time.Minute
	defaultOperationTimeout = 2 * time.Minute
	defaultPodExecTimeout   = 45 * time.Second

	// Environment variables used in e2e tests.
	// the value of this envVar is the name of the cluster to create.
	installClusterOnlyEnvVar = "E2E_INSTALL_CLUSTER_ONLY"
	// set to "true" to skip cluster creation, image loading, and cluster destroy.
	useExistingClusterEnvVar = "E2E_USE_EXISTING_CLUSTER"
	// selects the data-plane provider to set up (istio, cilium or calico).
	providerEnvVar        = "E2E_PROVIDER"
	providerVersionEnvVar = "E2E_PROVIDER_VERSION"
	// comma-separated list of optional dependencies to install: provider name
	// ("istio", "cilium", "calico") and "cert-manager". Empty/unset means all.
	// "none" means none.
	e2eDependenciesEnvVar = "E2E_DEPENDENCIES"
)

type provider struct {
	name    string
	version string
}

type suiteConfig struct {
	kindConfigPath          string
	logsDir                 string
	chartPath               string
	releaseName             string
	releaseNS               string
	controllerImage         string
	namespacePrefix         string
	provider                provider
	wnpStatusUpdateInterval time.Duration
	installClusterOnly      string
	useExistingCluster      bool
	hasNoDependencies       bool
	dependencies            []string
}

func loadSuiteConfig() suiteConfig {
	dependencies := os.Getenv(e2eDependenciesEnvVar)
	providerName := readEnvOrDefault(providerEnvVar, string(netypes.ProviderIstio))
	return suiteConfig{
		logsDir:         defaultLogsDir,
		chartPath:       defaultChartPath,
		releaseName:     defaultReleaseName,
		releaseNS:       defaultReleaseNS,
		controllerImage: defaultControllerImage,
		namespacePrefix: defaultNamespacePref,
		kindConfigPath:  defaultKindConfigPathForProvider(providerName),
		provider: provider{
			name: providerName,
			// we don't have a default value here, it will be set by provider specific code.
			version: readEnvOrDefault(providerVersionEnvVar, ""),
		},
		wnpStatusUpdateInterval: defaultWnpStatusUpdateInterval,
		installClusterOnly:      readEnvOrDefault(installClusterOnlyEnvVar, ""),
		useExistingCluster:      readEnvOrDefault(useExistingClusterEnvVar, "") != "",
		hasNoDependencies:       dependencies == "none",
		dependencies: func() []string {
			if d := strings.TrimSpace(dependencies); d != "" {
				return strings.Split(d, ",")
			}
			return nil
		}(),
	}
}

func readEnvOrDefault(name, defaultValue string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return defaultValue
	}
	return value
}

func defaultKindConfigPathForProvider(providerName string) string {
	switch providerName {
	case string(netypes.ProviderCilium), string(netypes.ProviderCalico):
		return defaultKindConfigNoCNIPath
	default:
		return defaultKindConfigIstioPath
	}
}

func (c suiteConfig) ProviderName() string {
	return c.provider.name
}

func (c suiteConfig) IsIstioProvider() bool {
	return c.ProviderName() == string(netypes.ProviderIstio)
}

func (c suiteConfig) IsKubernetesProvider() bool {
	return c.ProviderName() == string(netypes.ProviderCilium) ||
		c.ProviderName() == string(netypes.ProviderCalico)
}

// hasE2EDependency returns true if name is an active e2e dependency.
// An empty E2E_DEPENDENCIES value means all dependencies are active.
// The special value "none" disables all.
func (c suiteConfig) HasE2EDependency(name string) bool {
	if c.hasNoDependencies {
		return false
	}
	if len(c.dependencies) == 0 {
		// unset or empty
		return true
	}
	return slices.Contains(c.dependencies, name)
}

func getCNIVersion(ctx context.Context, defaultVersion string) string {
	cniVersion := getSuiteConfig(ctx).provider.version
	if cniVersion != "" {
		return cniVersion
	}
	return defaultVersion
}
