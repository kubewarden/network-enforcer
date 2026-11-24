package workload

import (
	"context"
	"errors"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

// Get fetches the Pod and resolves it to a Workload.
func Get(
	ctx context.Context,
	c client.Client,
	podNamespacedName types.NamespacedName,
) (securityv1alpha1.WorkloadRef, error) {
	ref, _, err := GetWithOwnerUID(ctx, c, podNamespacedName)
	return ref, err
}

// GetWithOwnerUID resolves a Pod and returns the UID of its supported owner.
func GetWithOwnerUID(
	ctx context.Context,
	c client.Client,
	podNamespacedName types.NamespacedName,
) (securityv1alpha1.WorkloadRef, types.UID, error) {
	var pod corev1.Pod
	if err := c.Get(ctx, podNamespacedName, &pod); err != nil {
		return securityv1alpha1.WorkloadRef{}, "", fmt.Errorf("getting Pod %q: %w", podNamespacedName, err)
	}
	ref := GetNameAndKind(&pod)
	if !ref.IsSupported() {
		return ref, "", nil
	}
	uid, err := lookupPodSelectorForWorkload(ctx, c, &ref)
	if err != nil {
		return securityv1alpha1.WorkloadRef{}, "", fmt.Errorf(
			"failed to lookup %s %s/%s label selector: %w",
			ref.OwnerKind,
			ref.Namespace,
			ref.OwnerName,
			err,
		)
	}
	return ref, uid, nil
}

// GetNameAndKind resolves a Pod to its owning workload from controller
// OwnerReferences. Deployment pods are owned by a ReplicaSet; we infer the
// Deployment name from the pod-template-hash label. StatefulSet and DaemonSet
// own pods directly.
//
// Heuristics for additional kinds (Job/CronJob, OpenShift DeploymentConfig)
// live in runtime-enforcer's former getPodInfo and can be ported when needed:
// https://github.com/kubewarden/runtime-enforcer/pull/219/changes#diff-65f18bba13a51ac9c01c9f32f9c222070bb8f3dda11868f44c75889265381f5fL45
func GetNameAndKind(pod *corev1.Pod) securityv1alpha1.WorkloadRef {
	namespace := pod.Namespace
	ref := metav1.GetControllerOf(pod)
	if ref == nil {
		return securityv1alpha1.WorkloadRef{
			Namespace: namespace,
			OwnerKind: securityv1alpha1.WorkloadKindPod,
			OwnerName: pod.Name,
		}
	}

	kind, name := ref.Kind, ref.Name
	if kind == string(securityv1alpha1.WorkloadKindReplicaSet) {
		hash := pod.Labels[appsv1.DefaultDeploymentUniqueLabelKey]
		if hash == "" || !strings.HasSuffix(name, hash) {
			return securityv1alpha1.WorkloadRef{
				Namespace: namespace,
				OwnerKind: securityv1alpha1.WorkloadKindReplicaSet,
				OwnerName: name,
			}
		}
		kind = string(securityv1alpha1.WorkloadKindDeployment)
		name = strings.TrimSuffix(name, "-"+hash)
	}

	return securityv1alpha1.WorkloadRef{
		Namespace: namespace,
		OwnerKind: securityv1alpha1.WorkloadKind(kind),
		OwnerName: name,
	}
}

func LookupPodSelectorForWorkload(
	ctx context.Context,
	c client.Client,
	wk *securityv1alpha1.WorkloadRef,
) error {
	_, err := lookupPodSelectorForWorkload(ctx, c, wk)
	return err
}

func lookupPodSelectorForWorkload(
	ctx context.Context,
	c client.Client,
	wk *securityv1alpha1.WorkloadRef,
) (types.UID, error) {
	key := types.NamespacedName{Name: wk.OwnerName, Namespace: wk.Namespace}
	var selector *metav1.LabelSelector
	var uid types.UID
	switch wk.OwnerKind { //nolint:exhaustive // we don't support all workload kinds
	case securityv1alpha1.WorkloadKindDeployment:
		var deploy appsv1.Deployment
		if err := c.Get(ctx, key, &deploy); err != nil {
			return "", err
		}
		selector, uid = deploy.Spec.Selector, deploy.UID
	case securityv1alpha1.WorkloadKindStatefulSet:
		var sts appsv1.StatefulSet
		if err := c.Get(ctx, key, &sts); err != nil {
			return "", err
		}
		selector, uid = sts.Spec.Selector, sts.UID
	case securityv1alpha1.WorkloadKindDaemonSet:
		var ds appsv1.DaemonSet
		if err := c.Get(ctx, key, &ds); err != nil {
			return "", err
		}
		selector, uid = ds.Spec.Selector, ds.UID
	default:
		return "", fmt.Errorf("unsupported workload kind: %s", string(wk.OwnerKind))
	}

	if selector == nil {
		return "", errors.New("nil label selector not allowed")
	}

	s, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return "", fmt.Errorf("failed to convert label selector: %w", err)
	}
	if s.Empty() {
		return "", errors.New("empty selector not allowed")
	}
	wk.Selector = *selector
	return uid, nil
}

// ResolveDenyingPolicy finds the WorkloadNetworkPolicy associated with the workload violation
// by matching the workload's (targetRef, direction) A non-nil error means
// the owning policy could not be resolved: the lookup failed, no WNP targets the
// workload (ErrTargetNotFound), or more than one does (ErrDuplicateTarget).
func ResolveDenyingPolicy(
	ctx context.Context,
	c client.Reader,
	wk *securityv1alpha1.WorkloadRef,
	direction networkingv1.PolicyType,
) (types.NamespacedName, error) {
	wnp, err := LookupWNPByTarget(ctx, c, wk.Namespace, wk.OwnerKind, wk.OwnerName, direction)
	if err != nil {
		return types.NamespacedName{}, err
	}
	return wnp.NamespacedName(), nil
}

// OwnerObjectFor returns an empty typed client.Object for Deployment, StatefulSet,
// or DaemonSet. It returns nil for unsupported kinds.
func OwnerObjectFor(kind securityv1alpha1.WorkloadKind) client.Object {
	switch kind { //nolint:exhaustive // we don't support all workload kinds
	case securityv1alpha1.WorkloadKindDeployment:
		return &appsv1.Deployment{}
	case securityv1alpha1.WorkloadKindStatefulSet:
		return &appsv1.StatefulSet{}
	case securityv1alpha1.WorkloadKindDaemonSet:
		return &appsv1.DaemonSet{}
	default:
		return nil
	}
}
