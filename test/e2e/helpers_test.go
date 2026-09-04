package e2e_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/third_party/helm"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

type key string

const (
	suiteCfgKey = key("suiteConfig")
	loggerKey   = key("logger")
	clientKey   = key("client")
)

func injectSetupLogger() env.Func {
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
		return context.WithValue(ctx, loggerKey, slog.New(slog.NewJSONHandler(os.Stdout, nil))), nil
	}
}

func getSetupLogger(ctx context.Context) *slog.Logger {
	return ctx.Value(loggerKey).(*slog.Logger)
}

func injectSuiteConfig(sc suiteConfig) env.Func {
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
		return context.WithValue(ctx, suiteCfgKey, sc), nil
	}
}

func getSuiteConfig(ctx context.Context) suiteConfig {
	return ctx.Value(suiteCfgKey).(suiteConfig)
}

func injectSecurityV1Alpha1Client() env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		r, err := resources.New(config.Client().RESTConfig())
		if err != nil {
			return ctx, fmt.Errorf("cannot create k8s client: %w", err)
		}
		if err = securityv1alpha1.AddToScheme(r.GetScheme()); err != nil {
			return ctx, fmt.Errorf("cannot add securityv1alpha1 to scheme: %w", err)
		}
		if err = istiosecurityv1.AddToScheme(r.GetScheme()); err != nil {
			return ctx, fmt.Errorf("cannot add istio security v1 to scheme: %w", err)
		}
		return context.WithValue(ctx, clientKey, r), nil
	}
}

func getSecurityV1Alpha1Client(ctx context.Context) *resources.Resources {
	return ctx.Value(clientKey).(*resources.Resources)
}

func getNamespace(ctx context.Context) string {
	return ctx.Value(key("namespace")).(string)
}

func setupTestNamespace(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	// RandomName already adds a `-` so we need to trim it from our prefix
	testNamespace := envconf.RandomName(defaultNamespacePref, 32)
	t.Logf("creating test namespace: %q", testNamespace)
	err := getSecurityV1Alpha1Client(ctx).Create(ctx, &corev1.Namespace{
		Name: testNamespace})
	require.NoError(t, err, "failed to create test namespace %q", testNamespace)
	return context.WithValue(ctx, key("namespace"), testNamespace)
}

func teardownTestNamespace(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)

	ns := &corev1.Namespace{Name: namespace}
	err := getSecurityV1Alpha1Client(ctx).Delete(ctx, ns)
	if err != nil && !apierrors.IsNotFound(err) {
		require.NoError(t, err, "failed to delete namespace %q", namespace)
	}

	err = wait.For(
		conditions.New(getSecurityV1Alpha1Client(ctx)).ResourceDeleted(ns),
		wait.WithTimeout(defaultOperationTimeout),
	)
	require.NoError(t, err, "wait namespace deletion")

	return ctx
}

func addLocalChartRepo(ctx context.Context, manager *helm.Manager, localRepoName, repoURL string) error {
	getSetupLogger(ctx).InfoContext(ctx, "⬇️ adding local helm repo",
		"localName", localRepoName,
		"url", repoURL)
	if err := manager.RunRepo(helm.WithArgs("add", localRepoName, repoURL)); err != nil {
		return fmt.Errorf("failed to add local helm repo: %w", err)
	}
	// Refresh only the repo we just added: a global `helm repo update` would
	// also refresh every other repo configured on the machine (e.g. on shared
	// dev boxes or CI runners), and one unreachable repo would fail the whole
	// e2e setup.
	if err := manager.RunRepo(helm.WithArgs("update", localRepoName)); err != nil {
		return fmt.Errorf("failed to update local helm repo: %w", err)
	}
	return nil
}

func generateKindControlPlaneTolerations(prefix string) []helm.Option {
	return []helm.Option{
		helm.WithArgs("--set", fmt.Sprintf("%stolerations[0].key=node-role.kubernetes.io/control-plane", prefix)),
		helm.WithArgs("--set", fmt.Sprintf("%stolerations[0].operator=Exists", prefix)),
		helm.WithArgs("--set", fmt.Sprintf("%stolerations[0].effect=NoSchedule", prefix)),
	}
}
