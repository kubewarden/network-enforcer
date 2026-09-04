package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	netypes "github.com/kubewarden/network-enforcer/internal/types"
)

func newPromotedIstioWNP(namespacedName types.NamespacedName) *securityv1alpha1.WorkloadNetworkPolicy {
	return &securityv1alpha1.WorkloadNetworkPolicy{
		Name:      namespacedName.Name,
		Namespace: namespacedName.Namespace,
		Labels: map[string]string{
			securityv1alpha1.PolicyPromotedFromLabelKey: namespacedName.Name,
		},
		Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
			Mode: securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
			PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
				Backend: securityv1alpha1.PolicyBackendIstio,
				Istio: &securityv1alpha1.IstioAuthorizationPolicySpec{
					Selector: metav1.LabelSelector{
						MatchLabels: map[string]string{"example": "test-istio"},
					},
				},
			},
		},
	}
}

func TestProcessIstioLearningEvent(t *testing.T) {
	t.Parallel()

	const (
		clientPrincipal = "cluster.local/ns/default/sa/http-client-sa"
		otherPrincipal  = "cluster.local/ns/default/sa/other-client-sa"
	)

	httpServerRef := &securityv1alpha1.WorkloadRef{
		Namespace: "default",
		OwnerKind: securityv1alpha1.WorkloadKindDeployment,
		OwnerName: "http-server",
		Selector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "http-server"}},
	}

	newEvent := func(dstPort int32, srcIdentity string) netypes.LearningEvent {
		return netypes.LearningEvent{
			Source:  &securityv1alpha1.WorkloadRef{Identity: srcIdentity},
			Dest:    httpServerRef,
			DstPort: dstPort,
			Backend: securityv1alpha1.PolicyBackendIstio,
		}
	}

	assertHTTPProposal := func(t *testing.T, r *LearningReconciler, rules []securityv1alpha1.IstioAuthorizationPolicyRule) {
		t.Helper()
		proposal := getProposalMetadata(httpServerRef, networkingv1.PolicyTypeIngress)
		err := r.Get(t.Context(), proposal.NamespacedName(), proposal)
		require.NoError(t, err)
		require.Equal(t, securityv1alpha1.PolicyBackendIstio, proposal.Spec.Backend)
		require.NotNil(t, proposal.Spec.Istio)
		require.Nil(t, proposal.Spec.Kubernetes)
		require.Equal(t, httpServerRef.Selector, proposal.Spec.Istio.Selector)
		require.ElementsMatch(t, rules, proposal.Spec.Istio.Rules)
	}

	tests := []struct {
		name   string
		objs   []client.Object
		events []netypes.LearningEvent
		assert func(*testing.T, *LearningReconciler)
	}{
		{
			name: "stable_proposal_per_deployment_across_replicas",
			objs: []client.Object{
				&appsv1.Deployment{Name: "http-server", Namespace: "default"},
			},
			events: []netypes.LearningEvent{
				// we simulate the same connection seen by different replicas
				newEvent(18080, clientPrincipal),
				newEvent(18080, clientPrincipal),
			},
			assert: func(t *testing.T, r *LearningReconciler) {
				assertHTTPProposal(t, r, []securityv1alpha1.IstioAuthorizationPolicyRule{
					{
						From: []securityv1alpha1.IstioFrom{
							{Source: securityv1alpha1.IstioSource{Principals: []string{clientPrincipal}}},
						},
						To: []securityv1alpha1.IstioTo{
							{Operation: securityv1alpha1.IstioOperation{Ports: []string{"18080"}}},
						},
					},
				})
			},
		},
		{
			name: "merges_ports_and_principals",
			objs: []client.Object{
				&appsv1.Deployment{Name: "http-server", Namespace: "default"},
			},
			events: []netypes.LearningEvent{
				newEvent(18080, clientPrincipal),
				newEvent(18081, clientPrincipal),
				newEvent(18080, clientPrincipal),
				newEvent(18080, otherPrincipal),
			},
			assert: func(t *testing.T, r *LearningReconciler) {
				assertHTTPProposal(t, r, []securityv1alpha1.IstioAuthorizationPolicyRule{
					{
						From: []securityv1alpha1.IstioFrom{
							{Source: securityv1alpha1.IstioSource{Principals: []string{clientPrincipal}}},
						},
						To: []securityv1alpha1.IstioTo{
							{Operation: securityv1alpha1.IstioOperation{Ports: []string{"18080", "18081"}}},
						},
					},
					{
						From: []securityv1alpha1.IstioFrom{
							{Source: securityv1alpha1.IstioSource{Principals: []string{otherPrincipal}}},
						},
						To: []securityv1alpha1.IstioTo{
							{Operation: securityv1alpha1.IstioOperation{Ports: []string{"18080"}}},
						},
					},
				})
			},
		},
		{
			name: "skips_when_promoted_policy_exists",
			objs: []client.Object{
				newPromotedIstioWNP(
					getProposalMetadata(httpServerRef, networkingv1.PolicyTypeIngress).NamespacedName(),
				),
			},
			events: []netypes.LearningEvent{
				newEvent(18080, clientPrincipal),
			},
			assert: func(t *testing.T, r *LearningReconciler) {
				proposal := getProposalMetadata(httpServerRef, networkingv1.PolicyTypeIngress)
				err := r.Get(t.Context(), proposal.NamespacedName(), proposal)
				require.True(t, apierrors.IsNotFound(err), "expected proposal to be skipped, but it was found")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newTestLearningReconciler(t, tt.objs)

			for _, evt := range tt.events {
				_, err := r.Reconcile(t.Context(), evt)
				require.NoError(t, err)
			}
			tt.assert(t, r)
		})
	}
}
