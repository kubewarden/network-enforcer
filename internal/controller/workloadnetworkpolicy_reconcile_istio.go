package controller

import (
	"context"
	"fmt"
	"maps"

	"github.com/go-logr/logr"
	istiosecurityv1beta1 "istio.io/api/security/v1beta1"
	istiotypev1beta1 "istio.io/api/type/v1beta1"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

// this annotation is experimental inside istio but for now we use it for monitor mode.
// https://istio.io/latest/docs/tasks/security/authorization/authz-dry-run/#limitations
const istioDryRunAnnotationKey = "istio.io/dry-run"

func (r *WorkloadNetworkPolicyReconciler) reconcileIstioPolicy(
	ctx context.Context,
	log logr.Logger,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
) error {
	ap := &istiosecurityv1.AuthorizationPolicy{
		Name:      wnp.Name,
		Namespace: wnp.Namespace,
	}
	err := r.Get(ctx, wnp.NamespacedName(), ap)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to get AuthorizationPolicy: %w", err)
	}
	if err == nil {
		// if the policy exists it should be controlled by the WorkloadNetworkPolicy
		// we just log an error and we stop the reconciliation since we cannot do anything from the controller.
		if !metav1.IsControlledBy(ap, wnp) {
			log.Error(err, "refusing to manage existing AuthorizationPolicy not controlled by a WorkloadNetworkPolicy",
				"namespace", ap.Namespace,
				"name", ap.Name,
			)
			return nil
		}
	}

	if _, err = controllerutil.CreateOrPatch(ctx, r.Client, ap, func() error {
		populateIstioAuthorizationPolicySpec(&ap.Spec, wnp.Spec.Istio)

		if ap.Annotations == nil {
			ap.Annotations = map[string]string{}
		}

		if wnp.Spec.Mode == securityv1alpha1.WorkloadNetworkPolicyModeMonitor {
			ap.Annotations[istioDryRunAnnotationKey] = "true"
		} else {
			delete(ap.Annotations, istioDryRunAnnotationKey)
		}
		return controllerutil.SetControllerReference(wnp, ap, r.Scheme)
	}); err != nil {
		return fmt.Errorf("failed to reconcile NetworkPolicy: %w", err)
	}
	return nil
}

func populateIstioAuthorizationPolicySpec(
	spec *istiosecurityv1beta1.AuthorizationPolicy,
	backendSpec *securityv1alpha1.IstioAuthorizationPolicySpec,
) {
	// by default for now we set the policy to allow
	spec.Action = istiosecurityv1beta1.AuthorizationPolicy_ALLOW

	// Selector
	spec.Selector = &istiotypev1beta1.WorkloadSelector{
		MatchLabels: map[string]string{},
	}
	maps.Copy(spec.GetSelector().GetMatchLabels(), backendSpec.Selector.MatchLabels)

	// Rules
	spec.Rules = make([]*istiosecurityv1beta1.Rule, 0, len(backendSpec.Rules))
	for _, backendRule := range backendSpec.Rules {
		rule := &istiosecurityv1beta1.Rule{}

		if len(backendRule.From) > 0 {
			rule.From = make([]*istiosecurityv1beta1.Rule_From, 0, len(backendRule.From))
			for _, backendFrom := range backendRule.From {
				rule.From = append(rule.From, &istiosecurityv1beta1.Rule_From{
					Source: &istiosecurityv1beta1.Source{
						Principals: append([]string(nil), backendFrom.Source.Principals...),
					},
				})
			}
		}

		if len(backendRule.To) > 0 {
			rule.To = make([]*istiosecurityv1beta1.Rule_To, 0, len(backendRule.To))
			for _, backendTo := range backendRule.To {
				rule.To = append(rule.To, &istiosecurityv1beta1.Rule_To{
					Operation: &istiosecurityv1beta1.Operation{
						Ports: append([]string(nil), backendTo.Operation.Ports...),
					},
				})
			}
		}
		spec.Rules = append(spec.Rules, rule)
	}
}
