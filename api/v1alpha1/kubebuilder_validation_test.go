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
						},
					},
				},
			},
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
				},
			},
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
}
