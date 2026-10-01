package v1alpha1

import (
	"path/filepath"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

func TestValidationAdmissionPolicies(t *testing.T) {
	testEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "charts", "network-enforcer", "templates", "crd")},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := testEnv.Start()
	require.NoError(t, err, "cannot start envtest")
	defer func() {
		require.NoError(t, testEnv.Stop())
	}()

	require.NoError(t, AddToScheme(scheme.Scheme))

	// this is a client for the in-memory api server created by testEnv
	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
	require.NoError(t, err, "cannot create k8s client")

	objectMeta := metav1.ObjectMeta{
		Name:      "example",
		Namespace: "default",
	}
	ingressTarget := exampleTarget(networkingv1.PolicyTypeIngress)

	tests := []struct {
		name      string
		policy    *WorkloadNetworkPolicy
		isInvalid bool
	}{
		{
			name: "kubernetes_backend_should_not_be_present",
			policy: &WorkloadNetworkPolicy{
				ObjectMeta: objectMeta,
				Spec: WorkloadNetworkPolicySpec{
					Mode: WorkloadNetworkPolicyModeMonitor,
					PolicyBackendSpec: PolicyBackendSpec{
						Backend:    PolicyBackendIstio,
						Istio:      &IstioAuthorizationPolicySpec{},
						Kubernetes: &networkingv1.NetworkPolicySpec{},
					},
					WorkloadTargetingSpec: ingressTarget,
				},
			},
			isInvalid: true,
		},
		{
			name: "istio_spec_is_missing",
			policy: &WorkloadNetworkPolicy{
				ObjectMeta: objectMeta,
				Spec: WorkloadNetworkPolicySpec{
					Mode: WorkloadNetworkPolicyModeMonitor,
					PolicyBackendSpec: PolicyBackendSpec{
						Backend: PolicyBackendIstio,
						Istio:   nil,
					},
					WorkloadTargetingSpec: ingressTarget,
				},
			},
			isInvalid: true,
		},
		{
			name: "istio_backend_should_not_be_present",
			policy: &WorkloadNetworkPolicy{
				ObjectMeta: objectMeta,
				Spec: WorkloadNetworkPolicySpec{
					Mode: WorkloadNetworkPolicyModeMonitor,
					PolicyBackendSpec: PolicyBackendSpec{
						Backend:    PolicyBackendKubernetes,
						Istio:      &IstioAuthorizationPolicySpec{},
						Kubernetes: &networkingv1.NetworkPolicySpec{},
					},
					WorkloadTargetingSpec: ingressTarget,
				},
			},
			isInvalid: true,
		},
		{
			name: "kubernetes_spec_is_missing",
			policy: &WorkloadNetworkPolicy{
				ObjectMeta: objectMeta,
				Spec: WorkloadNetworkPolicySpec{
					Mode: WorkloadNetworkPolicyModeMonitor,
					PolicyBackendSpec: PolicyBackendSpec{
						Backend:    PolicyBackendKubernetes,
						Kubernetes: nil,
					},
					WorkloadTargetingSpec: ingressTarget,
				},
			},
			isInvalid: true,
		},
		{
			name: "kubernetes_empty_selector",
			policy: &WorkloadNetworkPolicy{
				ObjectMeta: objectMeta,
				Spec: WorkloadNetworkPolicySpec{
					Mode: WorkloadNetworkPolicyModeMonitor,
					PolicyBackendSpec: PolicyBackendSpec{
						Backend: PolicyBackendKubernetes,
						Kubernetes: &networkingv1.NetworkPolicySpec{
							PodSelector: metav1.LabelSelector{
								MatchLabels:      map[string]string{},
								MatchExpressions: nil,
							},
						},
					},
					WorkloadTargetingSpec: ingressTarget,
				},
			},
			isInvalid: true,
		},
		{
			name: "istio_empty_selector",
			policy: &WorkloadNetworkPolicy{
				ObjectMeta: objectMeta,
				Spec: WorkloadNetworkPolicySpec{
					Mode: WorkloadNetworkPolicyModeMonitor,
					PolicyBackendSpec: PolicyBackendSpec{
						Backend: PolicyBackendIstio,
						Istio: &IstioAuthorizationPolicySpec{
							Selector: metav1.LabelSelector{
								MatchLabels:      map[string]string{},
								MatchExpressions: nil,
							},
						},
					},
					WorkloadTargetingSpec: ingressTarget,
				},
			},
			isInvalid: true,
		},
		{
			name: "kubernetes_valid_policy",
			policy: &WorkloadNetworkPolicy{
				Name:      "valid-k8s",
				Namespace: "default",
				Spec: WorkloadNetworkPolicySpec{
					Mode: WorkloadNetworkPolicyModeMonitor,
					PolicyBackendSpec: PolicyBackendSpec{
						Backend: PolicyBackendKubernetes,
						Kubernetes: &networkingv1.NetworkPolicySpec{
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "example",
								},
								MatchExpressions: nil,
							},
							PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
						},
					},
					WorkloadTargetingSpec: exampleTarget(networkingv1.PolicyTypeEgress),
				},
			},
		},
		{
			name: "kubernetes_direction_policy_types_mismatch",
			policy: &WorkloadNetworkPolicy{
				ObjectMeta: objectMeta,
				Spec: WorkloadNetworkPolicySpec{
					Mode: WorkloadNetworkPolicyModeMonitor,
					PolicyBackendSpec: PolicyBackendSpec{
						Backend: PolicyBackendKubernetes,
						Kubernetes: &networkingv1.NetworkPolicySpec{
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "example"},
							},
							PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
						},
					},
					WorkloadTargetingSpec: exampleTarget(networkingv1.PolicyTypeIngress),
				},
			},
			isInvalid: true,
		},
		{
			name: "istio_valid_policy",
			policy: &WorkloadNetworkPolicy{
				Name:      "valid-istio",
				Namespace: "default",
				Spec: WorkloadNetworkPolicySpec{
					Mode: WorkloadNetworkPolicyModeMonitor,
					PolicyBackendSpec: PolicyBackendSpec{
						Backend: PolicyBackendIstio,
						Istio: &IstioAuthorizationPolicySpec{
							Selector: metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "example",
								},
								MatchExpressions: nil,
							},
						},
					},
					WorkloadTargetingSpec: ingressTarget,
				},
			},
		},
		{
			name: "missing_target_ref",
			policy: &WorkloadNetworkPolicy{
				ObjectMeta: objectMeta,
				Spec: WorkloadNetworkPolicySpec{
					Mode: WorkloadNetworkPolicyModeMonitor,
					PolicyBackendSpec: PolicyBackendSpec{
						Backend: PolicyBackendKubernetes,
						Kubernetes: &networkingv1.NetworkPolicySpec{
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "example"},
							},
						},
					},
					WorkloadTargetingSpec: WorkloadTargetingSpec{
						Direction: networkingv1.PolicyTypeIngress,
					},
				},
			},
			isInvalid: true,
		},
		{
			name: "missing_direction",
			policy: &WorkloadNetworkPolicy{
				ObjectMeta: objectMeta,
				Spec: WorkloadNetworkPolicySpec{
					Mode: WorkloadNetworkPolicyModeMonitor,
					PolicyBackendSpec: PolicyBackendSpec{
						Backend: PolicyBackendKubernetes,
						Kubernetes: &networkingv1.NetworkPolicySpec{
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "example"},
							},
						},
					},
					WorkloadTargetingSpec: WorkloadTargetingSpec{
						TargetRef: WorkloadTargetRef{
							Kind: WorkloadKindDeployment,
							Name: "example",
						},
					},
				},
			},
			isInvalid: true,
		},
		{
			name: "unsupported_target_kind",
			policy: &WorkloadNetworkPolicy{
				ObjectMeta: objectMeta,
				Spec: WorkloadNetworkPolicySpec{
					Mode: WorkloadNetworkPolicyModeMonitor,
					PolicyBackendSpec: PolicyBackendSpec{
						Backend: PolicyBackendKubernetes,
						Kubernetes: &networkingv1.NetworkPolicySpec{
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "example"},
							},
						},
					},
					WorkloadTargetingSpec: WorkloadTargetingSpec{
						TargetRef: WorkloadTargetRef{
							Kind: WorkloadKindPod,
							Name: "example",
						},
						Direction: networkingv1.PolicyTypeIngress,
					},
				},
			},
			isInvalid: true,
		},
		{
			name: "empty_target_name",
			policy: &WorkloadNetworkPolicy{
				ObjectMeta: objectMeta,
				Spec: WorkloadNetworkPolicySpec{
					Mode: WorkloadNetworkPolicyModeMonitor,
					PolicyBackendSpec: PolicyBackendSpec{
						Backend: PolicyBackendKubernetes,
						Kubernetes: &networkingv1.NetworkPolicySpec{
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "example"},
							},
						},
					},
					WorkloadTargetingSpec: WorkloadTargetingSpec{
						TargetRef: WorkloadTargetRef{
							Kind: WorkloadKindDeployment,
							Name: "",
						},
						Direction: networkingv1.PolicyTypeIngress,
					},
				},
			},
			isInvalid: true,
		},
		{
			name: "invalid_target_name",
			policy: &WorkloadNetworkPolicy{
				ObjectMeta: objectMeta,
				Spec: WorkloadNetworkPolicySpec{
					Mode: WorkloadNetworkPolicyModeMonitor,
					PolicyBackendSpec: PolicyBackendSpec{
						Backend: PolicyBackendKubernetes,
						Kubernetes: &networkingv1.NetworkPolicySpec{
							PodSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "example"},
							},
						},
					},
					WorkloadTargetingSpec: WorkloadTargetingSpec{
						TargetRef: WorkloadTargetRef{
							Kind: WorkloadKindDeployment,
							Name: "Invalid_Name",
						},
						Direction: networkingv1.PolicyTypeIngress,
					},
				},
			},
			isInvalid: true,
		},
		{
			name: "istio_egress_is_rejected",
			policy: &WorkloadNetworkPolicy{
				ObjectMeta: objectMeta,
				Spec: WorkloadNetworkPolicySpec{
					Mode: WorkloadNetworkPolicyModeMonitor,
					PolicyBackendSpec: PolicyBackendSpec{
						Backend: PolicyBackendIstio,
						Istio: &IstioAuthorizationPolicySpec{
							Selector: metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "example"},
							},
						},
					},
					WorkloadTargetingSpec: exampleTarget(networkingv1.PolicyTypeEgress),
				},
			},
			isInvalid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err = k8sClient.Create(t.Context(), tt.policy)
			if tt.isInvalid {
				require.True(t, apierrors.IsInvalid(err))
				return
			}
			require.NoError(t, err)
		})
	}

	proposalTests := []struct {
		name      string
		proposal  *WorkloadNetworkPolicyProposal
		isInvalid bool
	}{
		{
			name: "istio_egress_is_rejected",
			proposal: &WorkloadNetworkPolicyProposal{
				Name: "istio-egress", Namespace: "default",
				Spec: WorkloadNetworkPolicyProposalSpec{
					PolicyBackendSpec: PolicyBackendSpec{
						Backend: PolicyBackendIstio,
						Istio: &IstioAuthorizationPolicySpec{
							Selector: metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "example"},
							},
						},
					},
					WorkloadTargetingSpec: exampleTarget(networkingv1.PolicyTypeEgress),
				},
			},
			isInvalid: true,
		},
		{
			name: "istio_ingress_is_valid",
			proposal: &WorkloadNetworkPolicyProposal{
				Name: "istio-ingress", Namespace: "default",
				Spec: WorkloadNetworkPolicyProposalSpec{
					PolicyBackendSpec: PolicyBackendSpec{
						Backend: PolicyBackendIstio,
						Istio: &IstioAuthorizationPolicySpec{
							Selector: metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "example"},
							},
						},
					},
					WorkloadTargetingSpec: ingressTarget,
				},
			},
		},
	}

	for _, tt := range proposalTests {
		t.Run("proposal_"+tt.name, func(t *testing.T) {
			err = k8sClient.Create(t.Context(), tt.proposal)
			if tt.isInvalid {
				require.True(t, apierrors.IsInvalid(err))
				return
			}
			require.NoError(t, err)
		})
	}
}

func exampleTarget(direction networkingv1.PolicyType) WorkloadTargetingSpec {
	return WorkloadTargetingSpec{
		TargetRef: WorkloadTargetRef{
			Kind: WorkloadKindDeployment,
			Name: "example",
		},
		Direction: direction,
	}
}
