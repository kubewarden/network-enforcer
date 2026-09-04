package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	istiosecurityv1beta1 "istio.io/api/security/v1beta1"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

func createIstioWorkloadNetworkPolicy(
	mode securityv1alpha1.WorkloadNetworkPolicyMode,
) *securityv1alpha1.WorkloadNetworkPolicy {
	wnp := newTestWNP("test-policy", "default")
	wnp.UID = types.UID("test-uid")
	wnp.Spec.Mode = mode
	wnp.Spec.PolicyBackendSpec = securityv1alpha1.PolicyBackendSpec{
		Backend: securityv1alpha1.PolicyBackendIstio,
		Istio: &securityv1alpha1.IstioAuthorizationPolicySpec{
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			Rules: []securityv1alpha1.IstioAuthorizationPolicyRule{
				{
					From: []securityv1alpha1.IstioFrom{
						{
							Source: securityv1alpha1.IstioSource{
								Principals: []string{"cluster.local/ns/default/sa/frontend"},
							},
						},
					},
					To: []securityv1alpha1.IstioTo{
						{
							Operation: securityv1alpha1.IstioOperation{
								Ports: []string{"8080"},
							},
						},
					},
				},
			},
		},
	}
	return wnp
}

func createAssociatedAuthorizationPolicy(
	mode securityv1alpha1.WorkloadNetworkPolicyMode,
) *istiosecurityv1.AuthorizationPolicy {
	wnp := createIstioWorkloadNetworkPolicy(mode)
	ap := &istiosecurityv1.AuthorizationPolicy{
		Name:      wnp.Name,
		Namespace: wnp.Namespace,
	}
	populateIstioAuthorizationPolicySpec(&ap.Spec, wnp.Spec.Istio)
	controller := true
	blockOwnerDeletion := true
	ap.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion:         securityv1alpha1.GroupVersion.String(),
			Kind:               securityv1alpha1.WorkloadNetworkPolicyKind,
			Name:               wnp.Name,
			UID:                wnp.UID,
			Controller:         &controller,
			BlockOwnerDeletion: &blockOwnerDeletion,
		},
	}

	if mode == securityv1alpha1.WorkloadNetworkPolicyModeMonitor {
		ap.Annotations = map[string]string{istioDryRunAnnotationKey: "true"}
	}
	return ap
}

func assertIstioPolicy(t *testing.T, expected, current *istiosecurityv1.AuthorizationPolicy) {
	t.Helper()

	require.Equal(t, expected.Name, current.Name)
	require.Equal(t, expected.Namespace, current.Namespace)
	require.Equal(t, expected.Annotations, current.Annotations)
	require.Equal(t, expected.OwnerReferences, current.OwnerReferences)
	require.Equal(t, expected.Spec.GetAction(), current.Spec.GetAction())
	require.True(t, proto.Equal(expected.Spec.GetSelector(), current.Spec.GetSelector()))
	require.Len(t, current.Spec.GetRules(), len(expected.Spec.GetRules()))
	for i := range expected.Spec.GetRules() {
		require.True(t, proto.Equal(expected.Spec.GetRules()[i], current.Spec.GetRules()[i]))
	}
}

func TestWorkloadNetworkPolicyReconcilerIstioProtect(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		setup      func() []client.Object
		expectedAP *istiosecurityv1.AuthorizationPolicy
	}{
		{
			name: "create_protect_mode",
			setup: func() []client.Object {
				return []client.Object{createIstioWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect)}
			},
			expectedAP: createAssociatedAuthorizationPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect),
		},
		{
			name: "create_monitor_mode",
			setup: func() []client.Object {
				return []client.Object{createIstioWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeMonitor)}
			},
			expectedAP: createAssociatedAuthorizationPolicy(securityv1alpha1.WorkloadNetworkPolicyModeMonitor),
		},
		{
			name: "not_controller_policy_exists",
			setup: func() []client.Object {
				ap := createAssociatedAuthorizationPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect)
				// we remove the owner reference
				ap.OwnerReferences = nil
				// the WNP is in monitor mode so we need to check that after the reconciliation the not associated policy is still in protect mode and not touched.
				return []client.Object{createIstioWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeMonitor), ap}
			},
			expectedAP: func() *istiosecurityv1.AuthorizationPolicy {
				ap := createAssociatedAuthorizationPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect)
				ap.OwnerReferences = nil
				return ap
			}(),
		},
		{
			name: "monitor_to_protect",
			setup: func() []client.Object {
				return []client.Object{
					createIstioWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect),
					createAssociatedAuthorizationPolicy(securityv1alpha1.WorkloadNetworkPolicyModeMonitor),
				}
			},
			expectedAP: createAssociatedAuthorizationPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect),
		},
		{
			name: "protect_to_monitor",
			setup: func() []client.Object {
				return []client.Object{
					createIstioWorkloadNetworkPolicy(securityv1alpha1.WorkloadNetworkPolicyModeMonitor),
					createAssociatedAuthorizationPolicy(securityv1alpha1.WorkloadNetworkPolicyModeProtect),
				}
			},
			expectedAP: createAssociatedAuthorizationPolicy(securityv1alpha1.WorkloadNetworkPolicyModeMonitor),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := types.NamespacedName{Name: "test-policy", Namespace: "default"}
			r := newTestWNPreconciler(t, tc.setup()...)
			_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key})
			require.NoError(t, err)
			currentAP := &istiosecurityv1.AuthorizationPolicy{}
			require.NoError(t, r.Get(t.Context(),
				types.NamespacedName{Name: tc.expectedAP.Name, Namespace: tc.expectedAP.Namespace}, currentAP))
			assertIstioPolicy(t, tc.expectedAP, currentAP)
		})
	}
}

func TestPopulateIstioAuthorizationPolicySpec(t *testing.T) {
	t.Parallel()

	backendSpec := &securityv1alpha1.IstioAuthorizationPolicySpec{
		Selector: metav1.LabelSelector{
			MatchLabels: map[string]string{
				"app":  "web",
				"tier": "frontend",
			},
		},
		Rules: []securityv1alpha1.IstioAuthorizationPolicyRule{
			{
				From: []securityv1alpha1.IstioFrom{
					{
						Source: securityv1alpha1.IstioSource{
							Principals: []string{
								"cluster.local/ns/default/sa/frontend",
								"cluster.local/ns/default/sa/gateway",
							},
						},
					},
				},
				To: []securityv1alpha1.IstioTo{
					{
						Operation: securityv1alpha1.IstioOperation{
							Ports: []string{"8080", "8443"},
						},
					},
				},
			},
		},
	}

	spec := &istiosecurityv1beta1.AuthorizationPolicy{}
	populateIstioAuthorizationPolicySpec(spec, backendSpec)

	require.Equal(t, istiosecurityv1beta1.AuthorizationPolicy_ALLOW, spec.GetAction())
	require.Equal(t, backendSpec.Selector.MatchLabels, spec.GetSelector().GetMatchLabels())
	require.Len(t, spec.GetRules(), 1)
	require.Len(t, spec.GetRules()[0].GetFrom(), 1)
	require.Equal(
		t,
		[]string{"cluster.local/ns/default/sa/frontend", "cluster.local/ns/default/sa/gateway"},
		spec.GetRules()[0].GetFrom()[0].GetSource().GetPrincipals(),
	)
	require.Len(t, spec.GetRules()[0].GetTo(), 1)
	require.Equal(t, []string{"8080", "8443"}, spec.GetRules()[0].GetTo()[0].GetOperation().GetPorts())

	backendSpec.Selector.MatchLabels["app"] = "api"
	backendSpec.Rules[0].From[0].Source.Principals[0] = "cluster.local/ns/default/sa/changed"
	backendSpec.Rules[0].To[0].Operation.Ports[0] = "9090"

	require.Equal(t, "web", spec.GetSelector().GetMatchLabels()["app"])
	require.Equal(
		t,
		[]string{"cluster.local/ns/default/sa/frontend", "cluster.local/ns/default/sa/gateway"},
		spec.GetRules()[0].GetFrom()[0].GetSource().GetPrincipals(),
	)
	require.Equal(t, []string{"8080", "8443"}, spec.GetRules()[0].GetTo()[0].GetOperation().GetPorts())
}
