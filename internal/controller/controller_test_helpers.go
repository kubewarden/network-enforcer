package controller

import (
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

const testLabelKey = "app"

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = securityv1alpha1.AddToScheme(s)
	_ = networkingv1.AddToScheme(s)
	_ = scheme.AddToScheme(s) // core/v1
	return s
}

func newTestWNP(name, namespace string) *securityv1alpha1.WorkloadNetworkPolicy {
	return &securityv1alpha1.WorkloadNetworkPolicy{
		Name:      name,
		Namespace: namespace,
		UID:       types.UID(name + "-uid"),
		Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
			Mode: securityv1alpha1.WorkloadNetworkPolicyModeProtect,
			PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
				Backend: securityv1alpha1.PolicyBackendKubernetes,
				Kubernetes: &networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{testLabelKey: "test"},
					},
				},
			},
		},
	}
}

func newOwnedNetworkPolicy(wnp *securityv1alpha1.WorkloadNetworkPolicy) *networkingv1.NetworkPolicy {
	controller := true
	blockOwnerDeletion := true
	return &networkingv1.NetworkPolicy{
		Name:      wnp.Name,
		Namespace: wnp.Namespace,
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion:         securityv1alpha1.GroupVersion.String(),
				Kind:               securityv1alpha1.WorkloadNetworkPolicyKind,
				Name:               wnp.Name,
				UID:                wnp.UID,
				Controller:         &controller,
				BlockOwnerDeletion: &blockOwnerDeletion,
			},
		},
		Spec: *wnp.Spec.Kubernetes,
	}
}
