package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSelectorExtraction(t *testing.T) {
	tests := []struct {
		name     string
		spec     *WorkloadNetworkPolicySpec
		selector *metav1.LabelSelector
	}{
		{
			name:     "nil_spec",
			spec:     nil,
			selector: nil,
		},
		{
			name: "no_kubernetes_backend",
			spec: &WorkloadNetworkPolicySpec{
				Backend:    PolicyBackendKubernetes,
				Kubernetes: nil,
			},
			selector: nil,
		},
		{
			name: "no_istio_backend",
			spec: &WorkloadNetworkPolicySpec{
				Backend: PolicyBackendIstio,
				Istio:   nil,
			},
			selector: nil,
		},
		{
			name: "kubernetes_backend",
			spec: &WorkloadNetworkPolicySpec{
				Backend: PolicyBackendKubernetes,
				Kubernetes: &v1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "my-app"},
					},
				},
			},
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "my-app"},
			},
		},
		{
			name: "istio_backend",
			spec: &WorkloadNetworkPolicySpec{
				Backend: PolicyBackendIstio,
				Istio: &IstioAuthorizationPolicySpec{
					Selector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "my-app"},
					},
				},
			},
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "my-app"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sel, err := tc.spec.GetSelector()
			if tc.selector == nil {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, *tc.selector, sel)
		})
	}
}
