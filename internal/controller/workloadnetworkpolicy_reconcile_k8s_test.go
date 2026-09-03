package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

func assertNetworkPolicy(t *testing.T, expected, current *networkingv1.NetworkPolicy) {
	t.Helper()
	require.Equal(t, expected.Name, current.Name)
	require.Equal(t, expected.Namespace, current.Namespace)
	require.Equal(t, expected.Spec, current.Spec)
	require.Equal(t, expected.OwnerReferences, current.OwnerReferences)
}

func newTestWNPreconciler(t *testing.T, objs ...client.Object) *WorkloadNetworkPolicyReconciler {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, securityv1alpha1.AddToScheme(scheme))
	require.NoError(t, networkingv1.AddToScheme(scheme))
	require.NoError(t, istiosecurityv1.AddToScheme(scheme))

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

	return &WorkloadNetworkPolicyReconciler{
		Client: cl,
		Scheme: scheme,
	}
}

func createWorkloadNetworkPolicy(
	mode securityv1alpha1.WorkloadNetworkPolicyMode,
) *securityv1alpha1.WorkloadNetworkPolicy {
	wnp := newTestWNP("test-policy", "default")
	wnp.UID = types.UID("test-uid")
	wnp.Spec.Mode = mode
	wnp.Spec.Kubernetes.PodSelector.MatchLabels = map[string]string{"app": "web"}
	wnp.Spec.Kubernetes.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
	wnp.Spec.Kubernetes.Ingress = []networkingv1.NetworkPolicyIngressRule{
		{
			From: []networkingv1.NetworkPolicyPeer{
				{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"role": "frontend"},
					},
				},
			},
		},
	}
	return wnp
}

func createAssociatedNetworkPolicy() *networkingv1.NetworkPolicy {
	return newOwnedNetworkPolicy(
		createWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect),
	)
}

func TestWorkloadNetworkPolicyReconcilerK8s(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		setup      func() []client.Object
		expectedNP *networkingv1.NetworkPolicy
	}{
		{
			name: "create_protect_mode",
			setup: func() []client.Object {
				return []client.Object{createWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect)}
			},
			expectedNP: createAssociatedNetworkPolicy(),
		},
		{
			name: "create_monitor_mode",
			setup: func() []client.Object {
				return []client.Object{createWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeMonitor)}
			},
			// in monitor mode we shouldn't create a NetworkPolicy
			expectedNP: nil,
		},
		{
			name: "update_policy_template",
			setup: func() []client.Object {
				wnp := createWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect)
				// Also seed an existing NetworkPolicy with old spec
				np := createAssociatedNetworkPolicy()
				np.Spec.PodSelector.MatchLabels["app"] = "old"
				return []client.Object{wnp, np}
			},
			expectedNP: createAssociatedNetworkPolicy(),
		},
		{
			name: "not_controller_policy_exists",
			setup: func() []client.Object {
				wnp := createWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeMonitor)
				// Seed an existing NetworkPolicy without owner references
				// we shouldn't delete it since it is not controlled by us.
				np := createAssociatedNetworkPolicy()
				np.OwnerReferences = nil
				return []client.Object{wnp, np}
			},
			expectedNP: func() *networkingv1.NetworkPolicy {
				np := createAssociatedNetworkPolicy()
				np.OwnerReferences = nil
				return np
			}(),
		},
		{
			name: "protect_to_monitor",
			setup: func() []client.Object {
				wnp := createWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeMonitor)
				// Seed a NetworkPolicy that exists from a previous protect mode
				np := createAssociatedNetworkPolicy()
				return []client.Object{wnp, np}
			},
			expectedNP: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := types.NamespacedName{Name: "test-policy", Namespace: "default"}
			r := newTestWNPreconciler(t, tc.setup()...)
			_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key})
			require.NoError(t, err)
			np := &networkingv1.NetworkPolicy{}
			err = r.Get(t.Context(), key, np)
			if tc.expectedNP == nil {
				require.True(t, apierrors.IsNotFound(err))
				return
			}
			require.NoError(t, err)
			assertNetworkPolicy(t, tc.expectedNP, np)
		})
	}
}
