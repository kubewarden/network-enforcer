package e2e_test

import (
	"context"
	"slices"
	"testing"
	"time"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

func assertEqualKubernetesWNPP(
	t assert.TestingT,
	expected, actual securityv1alpha1.WorkloadNetworkPolicyProposal,
) {
	// Metadata
	assert.Equal(t, expected.Name, actual.Name, "network policy proposal name does not match expected")
	assert.Equal(t, expected.Namespace, actual.Namespace, "network policy proposal namespace does not match expected")
	assert.Equal(
		t,
		expected.Spec.Backend,
		actual.Spec.Backend,
		"network policy proposal backend does not match expected",
	)
	assert.NotNil(t, actual.Spec.Kubernetes, "network policy proposal kubernetes spec is nil")
	k8sPolicySpec := actual.Spec.Kubernetes
	expectedK8sPolicySpec := expected.Spec.Kubernetes

	// Spec
	assert.ElementsMatch(
		t,
		expectedK8sPolicySpec.PolicyTypes,
		k8sPolicySpec.PolicyTypes,
		"network policy proposal policy types do not match expected",
	)
	assert.Equal(
		t,
		expectedK8sPolicySpec.PodSelector,
		k8sPolicySpec.PodSelector,
		"network policy proposal pod selector does not match expected",
	)
	assert.ElementsMatch(
		t,
		expectedK8sPolicySpec.Ingress,
		k8sPolicySpec.Ingress,
		"network policy proposal ingress rules do not match expected",
	)
	assert.ElementsMatch(
		t,
		expectedK8sPolicySpec.Egress,
		k8sPolicySpec.Egress,
		"network policy proposal egress rules do not match expected",
	)
}

const neverAssertionTime = 7 * time.Second

func TestKubernetesFlow(t *testing.T) {
	if !loadSuiteConfig().IsKubernetesProvider() {
		t.Skip("Skipping Kubernetes flow test: selected provider is not cilium or calico")
	}

	feature := features.New("Kubernetes learning, monitor and protect").
		Setup(setupTestNamespace).
		Setup(setupSimpleAppWorkload).
		Assess("Learn the client to server flow",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				return assertPacketSentFromClient(ctx, t, corev1.ProtocolTCP, simpleAppTCPServicePort)
			}).
		Assess("Check the Kubernetes proposals are generated", assessKubernetesProposalGenerated).
		Assess("Promote proposals into monitor policies", assessPolicyProposalsPromoted).
		Assess("Send traffic to UDP service in monitor mode",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				return assertPacketSentFromClient(ctx, t, corev1.ProtocolUDP, simpleAppUDPServicePort)
			}).
		Assess("Check violations in monitor mode", assessViolationsInMonitorMode).
		Assess("Check proposals are not regenerated in monitor mode", assessProposalsAreNotRegenerated).
		Assess("Check NetworkPolicies are created in protect mode", assessKubernetesPoliciesAreCreated).
		Assess("Send traffic to UDP service in protect mode",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				return assertPacketBlockedFromClient(ctx, t, corev1.ProtocolUDP, simpleAppUDPServicePort)
			}).
		Assess("Check violations are reported", assessViolationInProtectMode).
		Assess("Check TCP traffic is still allowed",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				return assertPacketSentFromClient(ctx, t, corev1.ProtocolTCP, simpleAppTCPServicePort)
			}).
		Teardown(teardownSimpleAppWorkload).
		Teardown(teardownTestNamespace).
		Feature()

	testEnv.Test(t, feature)
}

func assessKubernetesProposalGenerated(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)

	tcpProtocol := corev1.ProtocolTCP
	udpProtocol := corev1.ProtocolUDP
	dstPort := intstr.FromInt32(simpleAppTCPServicePort)
	dnsPort := intstr.FromInt32(53)

	expectedClientEgressProposal := securityv1alpha1.WorkloadNetworkPolicyProposal{
		Name:      "deployment-" + simpleAppClientDeploymentName + "-egress",
		Namespace: namespace,
		Spec: securityv1alpha1.WorkloadNetworkPolicyProposalSpec{
			PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
				Backend: securityv1alpha1.PolicyBackendKubernetes,
				Kubernetes: &networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": simpleAppClientDeploymentName},
					},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
					Egress: []networkingv1.NetworkPolicyEgressRule{
						{
							Ports: []networkingv1.NetworkPolicyPort{
								{
									Port:     &dstPort,
									Protocol: &tcpProtocol,
								},
							},
							To: []networkingv1.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{corev1.LabelMetadataName: namespace},
									},
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"app": simpleAppServerDeploymentName},
									},
								},
							},
						},
						{
							Ports: []networkingv1.NetworkPolicyPort{
								{
									Port:     &dnsPort,
									Protocol: &udpProtocol,
								},
							},
							To: []networkingv1.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{corev1.LabelMetadataName: "kube-system"},
									},
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"k8s-app": "kube-dns"},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	expectedServerIngressProposal := securityv1alpha1.WorkloadNetworkPolicyProposal{
		Name:      "deployment-" + simpleAppServerDeploymentName + "-ingress",
		Namespace: namespace,
		Spec: securityv1alpha1.WorkloadNetworkPolicyProposalSpec{
			PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
				Backend: securityv1alpha1.PolicyBackendKubernetes,
				Kubernetes: &networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": simpleAppServerDeploymentName},
					},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					Ingress: []networkingv1.NetworkPolicyIngressRule{
						{
							From: []networkingv1.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{corev1.LabelMetadataName: namespace},
									},
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"app": simpleAppClientDeploymentName},
									},
								},
							},
							Ports: []networkingv1.NetworkPolicyPort{
								{
									Port:     &dstPort,
									Protocol: &tcpProtocol,
								},
							},
						},
					},
				},
			},
		},
	}

	var proposals securityv1alpha1.WorkloadNetworkPolicyProposalList
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		err := getSecurityV1Alpha1Client(ctx).WithNamespace(namespace).List(ctx, &proposals)
		assert.NoError(c, err, "failed to list network policy proposals")
		if err != nil {
			return
		}

		proposalsByName := make(map[string]securityv1alpha1.WorkloadNetworkPolicyProposal, len(proposals.Items))
		for _, proposal := range proposals.Items {
			proposalsByName[proposal.Name] = proposal
		}

		clientEgressProposal, found := proposalsByName[expectedClientEgressProposal.Name]
		if assert.True(c, found, "expected client egress policy proposal was not generated") {
			assertEqualKubernetesWNPP(c, expectedClientEgressProposal, clientEgressProposal)
		}

		serverIngressProposal, found := proposalsByName[expectedServerIngressProposal.Name]
		if assert.True(c, found, "expected server ingress policy proposal was not generated") {
			assertEqualKubernetesWNPP(c, expectedServerIngressProposal, serverIngressProposal)
		}
	}, defaultOperationTimeout, 3*time.Second, "expected policy proposals were not generated")

	require.Len(t, proposals.Items, 2, "expected exactly 2 policy proposals to be generated")
	// We return the proposals so that other tests can use them
	return context.WithValue(ctx, key("proposals"), proposals.Items)
}

func assessPolicyProposalsPromoted(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()

	// we recover the proposal from the context.
	proposals := ctx.Value(key("proposals")).([]securityv1alpha1.WorkloadNetworkPolicyProposal)
	client := getSecurityV1Alpha1Client(ctx)

	policies := make([]securityv1alpha1.WorkloadNetworkPolicy, 0, len(proposals))
	for _, proposal := range proposals {
		// We promote the proposal to a policy.
		require.Eventually(t, func() bool {
			proposal.SetPromotionLabel(securityv1alpha1.WorkloadNetworkPolicyModeMonitor)
			return client.Update(ctx, &proposal) == nil
		}, defaultOperationTimeout, 1*time.Second,
			"failed to promote network policy proposal %q", proposal.NamespacedName().String())

		// We expect the policy to be created.
		var policy securityv1alpha1.WorkloadNetworkPolicy
		require.Eventually(t, func() bool {
			return client.Get(ctx, proposal.Name, proposal.Namespace, &policy) == nil
		}, defaultOperationTimeout, 1*time.Second, "Network policy %q is not created", proposal.NamespacedName().String())

		// Check the policy specs are correct.
		require.True(t, policy.HasPromotedLabel(proposal.Name))
		require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeMonitor, policy.Spec.Mode)
		require.Equal(t, proposal.Spec.PolicyBackendSpec, policy.Spec.PolicyBackendSpec)
		policies = append(policies, policy)

		// We expect the proposal to be deleted
		require.Eventually(t, func() bool {
			return apierrors.IsNotFound(client.Get(ctx, proposal.Name, proposal.Namespace, &proposal))
		}, defaultOperationTimeout, 1*time.Second, "network policy proposal %q was not deleted", proposal.NamespacedName().String())
	}
	return context.WithValue(ctx, key("policies"), policies)
}

func assertViolation(t *testing.T,
	policyNamespacedName types.NamespacedName,
	action securityv1alpha1.WorkloadNetworkPolicyMode,
	violation securityv1alpha1.ViolationRecord,
) {
	t.Helper()

	// in our test the policy and the workloads live all in the same namespace
	policyNamespace := policyNamespacedName.Namespace
	require.Equal(t, policyNamespacedName.Name, violation.DenyingPolicyName)
	require.Equal(t, policyNamespace, violation.DenyingPolicyNamespace)

	require.Equal(t, simpleAppClientDeploymentName, violation.Source.OwnerName)
	require.Equal(t, securityv1alpha1.WorkloadKindDeployment, violation.Source.OwnerKind)
	require.Equal(t, policyNamespace, violation.Source.Namespace)

	require.Equal(t, simpleAppServerDeploymentName, violation.Dest.OwnerName)
	require.Equal(t, securityv1alpha1.WorkloadKindDeployment, violation.Dest.OwnerKind)
	require.Equal(t, policyNamespace, violation.Dest.Namespace)

	require.Equal(t, corev1.ProtocolUDP, violation.Protocol)
	require.Equal(t, simpleAppUDPServerPort, violation.DstPort)
	require.Equal(t, action, violation.Action)
}

func assessViolationsInMonitorMode(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	storedPolicies := ctx.Value(key("policies")).([]securityv1alpha1.WorkloadNetworkPolicy)
	client := getSecurityV1Alpha1Client(ctx)

	for _, storedPolicy := range storedPolicies {
		require.Never(t, func() bool {
			var policy securityv1alpha1.WorkloadNetworkPolicy
			if err := client.Get(ctx, storedPolicy.Name, storedPolicy.Namespace, &policy); err != nil {
				return false
			}
			// the spec shouldn't change
			return !apiequality.Semantic.DeepEqual(storedPolicy.Spec.PolicyBackendSpec, policy.Spec.PolicyBackendSpec)
		}, neverAssertionTime, 1*time.Second, "Network policy is updated, but it should not be", storedPolicy.NamespacedName().String())

		var policy securityv1alpha1.WorkloadNetworkPolicy
		require.Eventually(t, func() bool {
			if err := client.Get(ctx, storedPolicy.Name, storedPolicy.Namespace, &policy); err != nil {
				return false
			}

			if len(policy.Status.Violations) == 0 {
				t.Logf("Network policy %q has no violations", policy.NamespacedName().String())
				return false
			}
			return true
		}, defaultOperationTimeout, 1*time.Second)

		// Both ingress and egress policy should have a violation since the traffic is flowing in the cluster.
		require.Len(t, policy.Status.Violations, 1)
		require.Empty(t, policy.Status.AcknowledgedViolations)
		require.Equal(t, int64(1), policy.Status.ViolationCount)
		require.Equal(t, int64(1), policy.Status.ActiveViolationCount)
		violation := policy.Status.Violations[0]
		assertViolation(t, policy.NamespacedName(), securityv1alpha1.WorkloadNetworkPolicyModeMonitor, violation)
	}
	return ctx
}

func assessProposalsAreNotRegenerated(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()

	// we recover the proposal from the context.
	storedProposals := ctx.Value(key("proposals")).([]securityv1alpha1.WorkloadNetworkPolicyProposal)
	client := getSecurityV1Alpha1Client(ctx)

	for _, proposal := range storedProposals {
		require.Never(t, func() bool {
			var p securityv1alpha1.WorkloadNetworkPolicyProposal
			// the error should be always not found
			return !apierrors.IsNotFound(client.Get(ctx, proposal.Name, proposal.Namespace, &p))
		}, neverAssertionTime, 1*time.Second, "Network policy proposal %q is created, but it should not be", proposal.NamespacedName().String())
	}
	return ctx
}

func assessKubernetesPoliciesAreCreated(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	storedPolicies := ctx.Value(key("policies")).([]securityv1alpha1.WorkloadNetworkPolicy)
	client := getSecurityV1Alpha1Client(ctx)

	// For each policy we change mode to protect
	for _, policy := range storedPolicies {
		require.Eventually(t, func() bool {
			if err := client.Get(ctx, policy.Name, policy.Namespace, &policy); err != nil {
				t.Logf("failed to get network policy %q: %v", policy.NamespacedName().String(), err)
				return false
			}
			policy.Spec.Mode = securityv1alpha1.WorkloadNetworkPolicyModeProtect
			if err := client.Update(ctx, &policy); err != nil {
				t.Logf("failed to update network policy %q: %v", policy.NamespacedName().String(), err)
				return false
			}
			return true
		}, defaultOperationTimeout, 1*time.Second)
	}

	// Now we check the k8s network policies are created
	// we want to do it in a separate for loop so that k8s network policies are created independently
	for _, policy := range storedPolicies {
		var k8sPolicy networkingv1.NetworkPolicy
		require.Eventually(t, func() bool {
			if err := client.Get(ctx, policy.Name, policy.Namespace, &k8sPolicy); err != nil {
				t.Logf("failed to get k8s network policy %q: %v", policy.NamespacedName().String(), err)
				return false
			}
			return true
		}, defaultOperationTimeout, 1*time.Second)

		require.Equal(
			t,
			*policy.Spec.Kubernetes,
			k8sPolicy.Spec,
			"Network policy %q spec is not equal to the expected spec",
			policy.NamespacedName().String(),
		)

		require.Equal(
			t,
			[]metav1.OwnerReference{{
				APIVersion:         securityv1alpha1.GroupVersion.String(),
				Kind:               "WorkloadNetworkPolicy",
				Name:               policy.Name,
				UID:                policy.UID,
				Controller:         func(b bool) *bool { return &b }(true),
				BlockOwnerDeletion: func(b bool) *bool { return &b }(true),
			}},
			k8sPolicy.OwnerReferences,
			"K8s Network policy associated with %q doesn't contain the expected owner references",
			policy.NamespacedName().String(),
		)
	}
	return ctx
}

func assessViolationInProtectMode(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	storedPolicies := ctx.Value(key("policies")).([]securityv1alpha1.WorkloadNetworkPolicy)
	client := getSecurityV1Alpha1Client(ctx)

	for _, policy := range storedPolicies {
		if slices.Contains(policy.Spec.Kubernetes.PolicyTypes, networkingv1.PolicyTypeEgress) {
			// for the egress policy we expect a violation
			require.Eventually(t, func() bool {
				if err := client.Get(ctx, policy.Name, policy.Namespace, &policy); err != nil {
					return false
				}
				t.Logf("found violations in egress policy %q: %v",
					policy.NamespacedName().String(), policy.Status.Violations)

				// we should have 2 violations, one in monitor and one in protect
				return len(policy.Status.Violations) == 2
				// even if the sync is pretty fast in e2e test (~3s)
				// the scraper will receive violations with a certain interval from the CNI (e.g. see `calicoAggregationInterval`)
				// for this reason we keep the timeout pretty high.
			}, defaultOperationTimeout, 1*time.Second)

			// Assert some fields on the violation
			require.Len(t, policy.Status.Violations, 2)
			require.Equal(t, int64(2), policy.Status.ActiveViolationCount)
			// ViolationCount tracks every scrape observation, including deduped
			// re-reports of the same logical violation. Calico Goldmane may
			// re-stream the same deny flow across aggregation windows.
			require.GreaterOrEqual(t, policy.Status.ViolationCount, int64(len(policy.Status.Violations)))

			// Even if the protect violation is generated after the monitor one, some CNI report the timestamp
			// as the starting time of the flow rather then the time the packet was dropped, so here we don't know
			// the order of the violations, it probably depends on the CNI.
			protectIndex := -1
			for i := range policy.Status.Violations {
				if policy.Status.Violations[i].Action == securityv1alpha1.WorkloadNetworkPolicyModeProtect {
					protectIndex = i
					break
				}
			}
			require.NotEqual(t, -1, protectIndex, "no violation with action 'protect' found")
			violation := policy.Status.Violations[protectIndex]
			assertViolation(t, policy.NamespacedName(), securityv1alpha1.WorkloadNetworkPolicyModeProtect, violation)
		} else {
			require.Never(t, func() bool {
				if err := client.Get(ctx, policy.Name, policy.Namespace, &policy); err != nil {
					return false
				}
				// we should only have monitor violations for ingress
				return len(policy.Status.Violations) != 1
			}, 2*getSuiteConfig(ctx).wnpStatusUpdateInterval, 1*time.Second)
		}
	}
	return ctx
}
