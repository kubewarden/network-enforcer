package e2e_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/require"
)

// ambientNamespaceLabel is the namespace label that enrolls a namespace (and
// the workloads created in it afterwards) in the Istio ambient mesh.
const ambientNamespaceLabel = "istio.io/dataplane-mode"

// Istio ambient mesh install (official Istio Helm charts).
const (
	istioRepoURL       = "https://istio-release.storage.googleapis.com/charts"
	istioRepoLocalName = defaultNamespacePref + "-istio"
	istioNamespace     = "istio-system"
	istioChartVersion  = "1.30.3"
)

// labelNamespaceAmbient enrolls the test namespace in the ambient mesh. It must
// run before the test workloads are created: the istio-cni plugin decides, at
// pod creation time, whether to redirect a pod's traffic to the local ztunnel.
func labelNamespaceAmbient(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)
	r := getSecurityV1Alpha1Client(ctx)

	ns := &corev1.Namespace{Name: namespace}
	require.NoError(t, r.Get(ctx, namespace, "", ns), "failed to get test namespace %q", namespace)
	if ns.Labels == nil {
		ns.Labels = map[string]string{}
	}
	ns.Labels[ambientNamespaceLabel] = "ambient"
	require.NoError(t, r.Update(ctx, ns), "failed to label test namespace %q as ambient", namespace)
	return ctx
}

// TestIstioFlow is the smoke test for the Istio path: it validates the whole
// learning data path (ztunnel access log → istio-fluent-bit → OTLP → istio
// scraper → learning controller → WorkloadNetworkPolicyProposal) with a single
// TCP connection between two in-mesh workloads, then exercises the full policy
// lifecycle on the learned proposal: promotion to a monitor policy (dry-run
// AuthorizationPolicy, violations observed but traffic allowed), followed by
// the switch to protect mode (real enforcement, violating traffic blocked and
// recorded as a violation).
func TestIstioFlow(t *testing.T) {
	if !loadSuiteConfig().IsIstioProvider() {
		t.Skip("Skipping Istio flow test: selected provider is not istio")
	}

	feature := features.New("Istio ambient learning, monitor and protect").
		Setup(setupTestNamespace).
		Setup(labelNamespaceAmbient).
		Setup(setupSimpleAppWorkload).
		Assess("Learn the client to server flow",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				return assertPacketSentFromClient(ctx, t, corev1.ProtocolTCP, simpleAppTCPServicePort)
			}).
		Assess("Check the Istio ingress proposal is generated", assessIstioProposalGenerated).
		Assess("Promote the proposal to a monitor policy", promoteIstioProposalToMonitor).
		Assess("Check the monitor AuthorizationPolicy", checkIstioAuthorizationPolicy(v1alpha1.WorkloadNetworkPolicyModeMonitor)).
		Assess("Matching traffic is still allowed in monitor mode", matchingTrafficAllowed).
		Assess("Violating traffic is observed in monitor mode", violatingTrafficObserved).
		Assess("Switch the policy to protect mode", switchIstioPolicyToProtect).
		Assess("Check the protect AuthorizationPolicy", checkIstioAuthorizationPolicy(v1alpha1.WorkloadNetworkPolicyModeProtect)).
		Assess("Matching traffic is still allowed in protect mode", matchingTrafficAllowed).
		Assess("Violating traffic is blocked in protect mode", violatingTrafficBlocked).
		Teardown(teardownSimpleAppWorkload).
		Teardown(teardownTestNamespace).
		Feature()

	testEnv.Test(t, feature)
}

func assessIstioProposalGenerated(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)

	expected := v1alpha1.WorkloadNetworkPolicyProposal{
		Name:      "deployment-" + simpleAppServerDeploymentName + "-ingress",
		Namespace: namespace,
		Spec: v1alpha1.WorkloadNetworkPolicyProposalSpec{
			PolicyBackendSpec: v1alpha1.PolicyBackendSpec{
				Backend: v1alpha1.PolicyBackendIstio,
				Istio: &v1alpha1.IstioAuthorizationPolicySpec{
					Selector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": simpleAppServerDeploymentName},
					},
					Rules: []v1alpha1.IstioAuthorizationPolicyRule{
						{
							From: []v1alpha1.IstioFrom{
								{Source: v1alpha1.IstioSource{
									Principals: []string{istioPrincipal(namespace, simpleAppClientServiceAccount)},
								}},
							},
							To: []v1alpha1.IstioTo{
								{Operation: v1alpha1.IstioOperation{
									Ports: []string{strconv.FormatInt(int64(simpleAppTCPServicePort), 10)},
								}},
							},
						},
					},
				},
			},
		},
	}

	var proposal v1alpha1.WorkloadNetworkPolicyProposal
	require.Eventually(t, func() bool {
		err := getSecurityV1Alpha1Client(ctx).WithNamespace(namespace).
			Get(ctx, expected.Name, namespace, &proposal)
		if err == nil {
			return true
		}
		t.Logf("Istio ingress proposal %q not available yet: %v", expected.Name, err)
		return false
	}, defaultOperationTimeout, 3*time.Second,
		"expected Istio ingress proposal %q was not generated", expected.Name)

	require.Equal(t, expected.Spec.Backend, proposal.Spec.Backend, "proposal backend does not match expected")
	require.NotNil(t, proposal.Spec.Istio, "proposal has no Istio backend spec")
	require.Equal(
		t,
		expected.Spec.Istio.Selector,
		proposal.Spec.Istio.Selector,
		"proposal selector does not match expected",
	)
	require.ElementsMatch(
		t,
		expected.Spec.Istio.Rules,
		proposal.Spec.Istio.Rules,
		"proposal rules do not match expected",
	)

	return ctx
}

// istioPrincipal returns the SPIFFE principal (without the spiffe:// prefix)
// Istio uses to identify a workload in the given namespace and service account.
func istioPrincipal(namespace, serviceAccount string) string {
	return fmt.Sprintf("cluster.local/ns/%s/sa/%s", namespace, serviceAccount)
}
