package e2e_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"istio.io/api/annotation"
	istiosecurityv1beta1 "istio.io/api/security/v1beta1"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/e2e-framework/pkg/envconf"

	"github.com/kubewarden/network-enforcer/api/v1alpha1"
)

// istioIngressProposalName is the name of the learned ingress proposal for the
// server workload (Istio ambient only produces ingress proposals).
const istioIngressProposalName = "deployment-" + simpleAppServerDeploymentName + "-ingress"

// promoteIstioProposalToMonitor promotes the learned proposal into a
// WorkloadNetworkPolicy in monitor mode and waits for the proposal to be
// consumed.
func promoteIstioProposalToMonitor(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)
	client := getSecurityV1Alpha1Client(ctx)

	var proposal v1alpha1.WorkloadNetworkPolicyProposal
	require.NoError(t, client.WithNamespace(namespace).Get(ctx, istioIngressProposalName, namespace, &proposal),
		"failed to get learned proposal %q", istioIngressProposalName)

	proposal.SetPromotionLabel(v1alpha1.WorkloadNetworkPolicyModeMonitor)
	require.NoError(t, client.Update(ctx, &proposal),
		"failed to promote proposal %q to monitor mode", proposal.NamespacedName().String())

	var policy v1alpha1.WorkloadNetworkPolicy
	require.Eventually(t, func() bool {
		return client.WithNamespace(namespace).Get(ctx, istioIngressProposalName, namespace, &policy) == nil
	}, defaultOperationTimeout, 1*time.Second,
		"WorkloadNetworkPolicy %q was not created after promotion", istioIngressProposalName)

	// Check the promoted policy specs are correct: it must carry the
	// promotion provenance label, run in monitor mode, and be a faithful copy
	// of the proposal backend spec.
	require.True(t, policy.HasPromotedLabel(proposal.Name),
		"policy should carry the promoted-from label %q", proposal.Name)
	require.Equal(t, v1alpha1.WorkloadNetworkPolicyModeMonitor, policy.Spec.Mode,
		"promoted policy mode does not match expected")
	require.Equal(t, proposal.Spec.PolicyBackendSpec, policy.Spec.PolicyBackendSpec,
		"promoted policy backend spec does not match the proposal")

	require.Eventually(t, func() bool {
		var p v1alpha1.WorkloadNetworkPolicyProposal
		return apierrors.IsNotFound(
			client.WithNamespace(namespace).Get(ctx, istioIngressProposalName, namespace, &p),
		)
	}, defaultOperationTimeout, 1*time.Second,
		"proposal %q was not deleted after promotion", istioIngressProposalName)

	return ctx
}

// checkIstioAuthorizationPolicy asserts the AuthorizationPolicy reconciled from
// the WorkloadNetworkPolicy: same name/namespace, ALLOW action, the learned
// selector and rules, and the dry-run annotation only in monitor mode.
func checkIstioAuthorizationPolicy(
	mode v1alpha1.WorkloadNetworkPolicyMode,
) func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	return func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
		t.Helper()
		namespace := getNamespace(ctx)
		client := getSecurityV1Alpha1Client(ctx)

		var ap istiosecurityv1.AuthorizationPolicy
		require.Eventually(t, func() bool {
			if err := client.WithNamespace(namespace).Get(ctx, istioIngressProposalName, namespace, &ap); err != nil {
				t.Logf("AuthorizationPolicy %q not available yet: %v", istioIngressProposalName, err)
				return false
			}
			// The dry-run annotation is the reconciliation marker for monitor
			// mode: presence (and value, when present) is asserted here so the
			// annotation checks stay in a single place.
			dryRun, hasDryRun := ap.Annotations[annotation.IoIstioDryRun.Name]
			if mode == v1alpha1.WorkloadNetworkPolicyModeMonitor {
				return hasDryRun && dryRun == "true"
			}
			return !hasDryRun
		}, defaultOperationTimeout, 1*time.Second,
			"AuthorizationPolicy %q is not in the expected %q state", istioIngressProposalName, mode)

		require.Equal(t, istiosecurityv1beta1.AuthorizationPolicy_ALLOW, ap.Spec.GetAction(),
			"AuthorizationPolicy action does not match expected")
		require.Equal(t,
			map[string]string{"app": simpleAppServerDeploymentName},
			ap.Spec.GetSelector().GetMatchLabels(),
			"AuthorizationPolicy selector does not match expected",
		)

		require.Len(t, ap.Spec.GetRules(), 1, "AuthorizationPolicy should have exactly one rule")
		rule := ap.Spec.GetRules()[0]
		require.Len(t, rule.GetFrom(), 1, "rule should have exactly one From")
		require.Equal(t,
			[]string{istioPrincipal(namespace, simpleAppClientServiceAccount)},
			rule.GetFrom()[0].GetSource().GetPrincipals(),
			"rule principals do not match expected",
		)
		require.Len(t, rule.GetTo(), 1, "rule should have exactly one To")
		require.Equal(t,
			[]string{strconv.FormatInt(int64(simpleAppTCPServicePort), 10)},
			rule.GetTo()[0].GetOperation().GetPorts(),
			"rule ports do not match expected",
		)
		return ctx
	}
}

// matchingTrafficAllowed asserts the client can still reach the server on the
// learned (policy-allowed) port.
func matchingTrafficAllowed(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	return assertPacketSentFromClient(ctx, t, corev1.ProtocolTCP, simpleAppTCPServicePort)
}

// violatingTrafficObserved sends TCP traffic to the service port the policy
// does not allow: in monitor (dry-run) mode the traffic still flows, and the
// rejection is recorded as a monitor violation on the policy.
func violatingTrafficObserved(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	assertPacketSentFromClient(ctx, t, corev1.ProtocolTCP, simpleAppViolatingServicePort)

	assertViolationWithAction(ctx, t, v1alpha1.WorkloadNetworkPolicyModeMonitor)
	return ctx
}

// switchIstioPolicyToProtect flips the WorkloadNetworkPolicy to protect mode.
func switchIstioPolicyToProtect(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)
	client := getSecurityV1Alpha1Client(ctx)

	require.Eventually(t, func() bool {
		var policy v1alpha1.WorkloadNetworkPolicy
		if err := client.WithNamespace(namespace).Get(ctx, istioIngressProposalName, namespace, &policy); err != nil {
			return false
		}
		policy.Spec.Mode = v1alpha1.WorkloadNetworkPolicyModeProtect
		return client.Update(ctx, &policy) == nil
	}, defaultOperationTimeout, 1*time.Second,
		"failed to switch policy %q to protect mode", istioIngressProposalName)

	return ctx
}

// violatingTrafficBlocked asserts TCP traffic to the non-policy service port
// is now blocked by the enforced AuthorizationPolicy and recorded as a
// protect violation. The destination ztunnel rejects the connection, but the
// client-side nc may still exit 0: the reliable signal is the missing echo.
func violatingTrafficBlocked(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	assertPacketBlockedFromClient(ctx, t, corev1.ProtocolTCP, simpleAppViolatingServicePort)

	assertViolationWithAction(ctx, t, v1alpha1.WorkloadNetworkPolicyModeProtect)
	return ctx
}

// assertViolationWithAction polls the policy status until a violation with the
// given action appears, then asserts the Istio ALLOW-miss violation semantics:
// TCP, destination is the server deployment, and the owning WorkloadNetworkPolicy
// recorded in the DenyingPolicy fields. Istio reports no denying policy on the
// wire for an ALLOW-miss, so the enricher resolves the owning WNP by selector
// match and records it there (see istio.Enricher); it is the policy under test.
func assertViolationWithAction(
	ctx context.Context,
	t *testing.T,
	action v1alpha1.WorkloadNetworkPolicyMode,
) {
	t.Helper()
	namespace := getNamespace(ctx)
	client := getSecurityV1Alpha1Client(ctx)

	var policy v1alpha1.WorkloadNetworkPolicy
	require.Eventually(t, func() bool {
		if err := client.WithNamespace(namespace).Get(ctx, istioIngressProposalName, namespace, &policy); err != nil {
			return false
		}
		for _, v := range policy.Status.Violations {
			if v.Action == action {
				return true
			}
		}
		t.Logf("no %q violation yet; current violations: %+v", action, policy.Status.Violations)
		return false
	}, defaultOperationTimeout, 1*time.Second,
		"expected a %q violation on policy %q", action, istioIngressProposalName)

	require.Equal(t, int64(len(policy.Status.Violations)), policy.Status.ActiveViolationCount,
		"ActiveViolationCount should equal the number of stored violations")
	require.GreaterOrEqual(t, policy.Status.ViolationCount, int64(len(policy.Status.Violations)),
		"ViolationCount should be at least the number of stored violations")

	var found bool
	for _, v := range policy.Status.Violations {
		if v.Action != action {
			continue
		}
		require.Equal(t, corev1.ProtocolTCP, v.Protocol, "violation protocol does not match expected")
		require.Equal(t, namespace, v.Dest.Namespace, "violation destination namespace does not match expected")
		require.True(t, strings.HasPrefix(v.Dest.OwnerName, simpleAppServerDeploymentName),
			"violation destination should be the server deployment, got %q", v.Dest.OwnerName)
		require.Equal(t, istioIngressProposalName, v.DenyingPolicyName,
			"ALLOW-miss violation should carry the owning WorkloadNetworkPolicy name")
		require.Equal(t, namespace, v.DenyingPolicyNamespace,
			"ALLOW-miss violation should carry the owning WorkloadNetworkPolicy namespace")
		found = true
		break
	}
	require.True(t, found, "no violation with action %q found for detailed assertion", action)
}
