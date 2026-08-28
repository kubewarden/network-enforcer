package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/ringbuf"
	netypes "github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/rancher-sandbox/network-enforcer/internal/violation"
)

func newTestLearningReconciler(t *testing.T, objs []client.Object) *LearningReconciler {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, securityv1alpha1.AddToScheme(scheme))

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		Build()
	r := NewLearningReconciler(cl, ringbuf.New[violation.Observation]())
	require.NotNil(t, r)
	return r
}

func newPromotedKubernetesWNP(
	namespacedName types.NamespacedName,
	mode securityv1alpha1.WorkloadNetworkPolicyMode,
) *securityv1alpha1.WorkloadNetworkPolicy {
	return &securityv1alpha1.WorkloadNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      namespacedName.Name,
			Namespace: namespacedName.Namespace,
			Labels: map[string]string{
				securityv1alpha1.PolicyPromotedFromLabelKey: namespacedName.Name,
			},
		},
		Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
			Mode: mode,
			PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
				Backend: securityv1alpha1.PolicyBackendKubernetes,
				Kubernetes: &networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"example": "test-k8s"},
					},
				},
			},
		},
	}
}

func TestProcessKubernetesLearningEvent(t *testing.T) {
	t.Parallel()

	newPort := func(port int) *intstr.IntOrString {
		p := intstr.FromInt(port)
		return &p
	}
	tcpProtocol := corev1.ProtocolTCP
	udpProtocol := corev1.ProtocolUDP

	frontendRef := &securityv1alpha1.WorkloadRef{
		Namespace: "default",
		OwnerKind: securityv1alpha1.WorkloadKindDeployment,
		OwnerName: "frontend",
		Selector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "frontend"}},
	}
	backendRef := &securityv1alpha1.WorkloadRef{
		Namespace: "default",
		OwnerKind: securityv1alpha1.WorkloadKindDeployment,
		OwnerName: "backend",
		Selector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "backend"}},
	}

	newEvent := func(dstPort int32, protocol corev1.Protocol) netypes.LearningEvent {
		return netypes.LearningEvent{
			Source:   frontendRef,
			Dest:     backendRef,
			DstPort:  dstPort,
			Protocol: protocol,
			Backend:  securityv1alpha1.PolicyBackendKubernetes,
		}
	}

	assertProposal := func(t *testing.T, r *LearningReconciler, direction networkingv1.PolicyType, ports []networkingv1.NetworkPolicyPort) {
		t.Helper()

		var workload *securityv1alpha1.WorkloadRef
		var peer *securityv1alpha1.WorkloadRef
		if direction == networkingv1.PolicyTypeEgress {
			workload = frontendRef
			peer = backendRef
		} else {
			workload = backendRef
			peer = frontendRef
		}

		proposal := getProposalMetadata(workload, direction)
		err := r.Get(t.Context(), proposal.NamespacedName(), proposal)
		require.NoError(t, err)

		require.Equal(t, securityv1alpha1.PolicyBackendKubernetes, proposal.Spec.Backend)
		require.NotNil(t, proposal.Spec.Kubernetes)
		require.Nil(t, proposal.Spec.Istio)
		require.Equal(t, workload.Selector, proposal.Spec.Kubernetes.PodSelector)
		require.Equal(t, []networkingv1.PolicyType{direction}, proposal.Spec.Kubernetes.PolicyTypes)

		if direction == networkingv1.PolicyTypeEgress {
			require.Nil(t, proposal.Spec.Kubernetes.Ingress)
			require.Len(t, proposal.Spec.Kubernetes.Egress, 1)
			require.Equal(t,
				[]networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{corev1.LabelMetadataName: peer.Namespace},
					},
					PodSelector: &peer.Selector,
				}},
				proposal.Spec.Kubernetes.Egress[0].To,
			)
			require.Equal(t, ports, proposal.Spec.Kubernetes.Egress[0].Ports)
		} else {
			require.Nil(t, proposal.Spec.Kubernetes.Egress)
			require.Len(t, proposal.Spec.Kubernetes.Ingress, 1)
			require.Equal(t,
				[]networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{corev1.LabelMetadataName: peer.Namespace},
					},
					PodSelector: &peer.Selector,
				}},
				proposal.Spec.Kubernetes.Ingress[0].From,
			)
			require.Equal(t, ports, proposal.Spec.Kubernetes.Ingress[0].Ports)
		}
	}

	assertProposals := func(t *testing.T, r *LearningReconciler, ports []networkingv1.NetworkPolicyPort) {
		// Client proposal
		assertProposal(t, r, networkingv1.PolicyTypeEgress, ports)
		// Server proposal
		assertProposal(t, r, networkingv1.PolicyTypeIngress, ports)
	}

	tests := []struct {
		name   string
		objs   []client.Object
		events []netypes.LearningEvent
		assert func(*testing.T, *LearningReconciler)
	}{
		{
			name: "stable_proposal_per_deployment_across_replicas",
			events: []netypes.LearningEvent{
				newEvent(8080, corev1.ProtocolTCP),
				newEvent(8080, corev1.ProtocolTCP),
			},
			assert: func(t *testing.T, r *LearningReconciler) {
				assertProposals(t, r, []networkingv1.NetworkPolicyPort{
					{
						Protocol: &tcpProtocol,
						Port:     newPort(8080),
					},
				})
			},
		},
		{
			name: "merges_ports_and_protocols",
			events: []netypes.LearningEvent{
				newEvent(8080, corev1.ProtocolTCP),
				newEvent(53, corev1.ProtocolUDP),
				newEvent(8080, corev1.ProtocolTCP),
			},
			assert: func(t *testing.T, r *LearningReconciler) {
				assertProposals(t, r, []networkingv1.NetworkPolicyPort{
					{
						Protocol: &tcpProtocol,
						Port:     newPort(8080),
					},
					{
						Protocol: &udpProtocol,
						Port:     newPort(53),
					},
				})
			},
		},
		{
			name: "skips_when_promoted_policies_in_protect_mode",
			objs: []client.Object{
				newPromotedKubernetesWNP(
					getProposalMetadata(frontendRef, networkingv1.PolicyTypeEgress).NamespacedName(),
					securityv1alpha1.WorkloadNetworkPolicyModeProtect,
				),
				newPromotedKubernetesWNP(
					getProposalMetadata(backendRef, networkingv1.PolicyTypeIngress).NamespacedName(),
					securityv1alpha1.WorkloadNetworkPolicyModeProtect,
				),
			},
			events: []netypes.LearningEvent{
				newEvent(8080, corev1.ProtocolTCP),
			},
			assert: func(t *testing.T, r *LearningReconciler) {
				egressProposal := getProposalMetadata(frontendRef, networkingv1.PolicyTypeEgress)
				err := r.Get(t.Context(), egressProposal.NamespacedName(), egressProposal)
				require.True(t, apierrors.IsNotFound(err), "expected egress proposal to be skipped")

				ingressProposal := getProposalMetadata(backendRef, networkingv1.PolicyTypeIngress)
				err = r.Get(t.Context(), ingressProposal.NamespacedName(), ingressProposal)
				require.True(t, apierrors.IsNotFound(err), "expected ingress proposal to be skipped")
			},
		},
		{
			name: "violations_when_policies_in_monitor_mode",
			objs: []client.Object{
				newPromotedKubernetesWNP(
					getProposalMetadata(frontendRef, networkingv1.PolicyTypeEgress).NamespacedName(),
					securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
				),
				newPromotedKubernetesWNP(
					getProposalMetadata(backendRef, networkingv1.PolicyTypeIngress).NamespacedName(),
					securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
				),
			},
			events: []netypes.LearningEvent{
				newEvent(8080, corev1.ProtocolTCP),
			},
			assert: func(t *testing.T, r *LearningReconciler) {
				observations := r.violationBuffer.Drain()
				require.Len(t, observations, 2)

				assertObservations := func(t *testing.T, obs violation.Observation, policyName string) {
					t.Helper()
					require.Equal(t, *frontendRef, obs.Source)
					require.Equal(t, *backendRef, obs.Dest)
					require.Equal(t, corev1.ProtocolTCP, obs.Protocol)
					require.Equal(t, int32(8080), obs.DstPort)
					require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeMonitor, obs.Action)
					require.Equal(t, policyName, obs.DenyingPolicyName)
					require.Equal(t, frontendRef.Namespace, obs.DenyingPolicyNamespace)
					require.Equal(t, securityv1alpha1.PolicyBackendKubernetes, obs.Provider)
				}

				egressViolation := observations[0]
				ingressViolation := observations[1]
				if observations[0].DenyingPolicyName != getProposalName(frontendRef, networkingv1.PolicyTypeEgress) {
					egressViolation, ingressViolation = observations[1], observations[0]
				}
				assertObservations(
					t,
					egressViolation,
					getProposalName(frontendRef, networkingv1.PolicyTypeEgress),
				)
				assertObservations(
					t,
					ingressViolation,
					getProposalName(backendRef, networkingv1.PolicyTypeIngress),
				)
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
