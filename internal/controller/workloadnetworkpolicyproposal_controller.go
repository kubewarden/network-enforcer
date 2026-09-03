package controller

import (
	"context"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/workload"
)

// WorkloadNetworkPolicyProposalReconciler reconciles WorkloadNetworkPolicyProposal objects.
type WorkloadNetworkPolicyProposalReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=networkenforcer.kubewarden.io,resources=workloadnetworkpolicyproposals,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networkenforcer.kubewarden.io,resources=workloadnetworkpolicies,verbs=get;list;watch;create;patch

func (r *WorkloadNetworkPolicyProposalReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	log.Info("workloadnetworkpolicyproposal", "req", req)

	var proposal securityv1alpha1.WorkloadNetworkPolicyProposal
	if err := r.Get(ctx, req.NamespacedName, &proposal); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if proposal.GetDeletionTimestamp() != nil {
		return ctrl.Result{}, nil
	}

	deleted, ownErr := r.reconcileOwnership(ctx, &proposal)
	if ownErr != nil {
		return ctrl.Result{}, ownErr
	}
	if deleted {
		return ctrl.Result{}, nil
	}

	// After a proposal is promoted and deleted, an agent can recreate a proposal
	// at the same time. If a WorkloadPolicy already exists with promoted-from=<proposalName>,
	// treat the proposal as leftover and delete it. This is eventually reconciled on the controller-runtime
	// resync (SyncPeriod, 10 hours by default) if both the proposal and the policy are still in the cluster.
	alreadyPromoted, err := hasPromotedPolicy(ctx, r.Client, proposal.Namespace, proposal.Name)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to check promoted WorkloadNetworkPolicy: %w", err)
	}
	if alreadyPromoted {
		log.Info(
			"Deleting WorkloadNetworkPolicyProposal because promoted WorkloadNetworkPolicy already exists",
			"proposal",
			proposal.Name,
		)
		if err = r.Delete(ctx, &proposal); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		return ctrl.Result{}, nil
	}

	mode, hasPromotionLabel := proposal.HasPromotionLabel()
	if !hasPromotionLabel {
		return ctrl.Result{}, nil
	}

	policy := securityv1alpha1.WorkloadNetworkPolicy{
		Name:      proposal.Name,
		Namespace: proposal.Namespace,
		Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
			Mode:              mode,
			PolicyBackendSpec: proposal.Spec.PolicyBackendSpec,
		},
	}
	if err = policy.SetPromotedLabel(proposal.Name); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to set promoted label: %w", err)
	}

	if err = r.Create(ctx, &policy); err != nil {
		if apierrors.IsAlreadyExists(err) {
			log.Info("WorkloadNetworkPolicy already exists, skipping creation",
				"policy", policy.NamespacedName().String())
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to create WorkloadNetworkPolicy: %w", err)
	}

	// Once we successfully promote the proposal into a policy, we no longer
	// need the proposal to remain in the cluster.
	if err = r.Delete(ctx, &proposal); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkloadNetworkPolicyProposalReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.WorkloadNetworkPolicyProposal{}).
		Named("workloadnetworkpolicyproposal").
		Complete(r)
}

// ownerRefFromProposalName recovers the owning workload kind and name from a
// learned proposal name. The naming convention is <kind>-<ownerName>-<direction>
// (e.g. "deployment-http-server-ingress"). It returns false when the name does
// not match any known kind prefix or direction suffix.
func ownerRefFromProposalName(namespace, proposalName string) (securityv1alpha1.WorkloadRef, bool) {
	knownKinds := []securityv1alpha1.WorkloadKind{
		securityv1alpha1.WorkloadKindDeployment,
		securityv1alpha1.WorkloadKindStatefulSet,
		securityv1alpha1.WorkloadKindDaemonSet,
	}
	knownSuffixes := []string{"-ingress", "-egress"}

	for _, kind := range knownKinds {
		prefix := strings.ToLower(string(kind)) + "-"
		if !strings.HasPrefix(proposalName, prefix) {
			continue
		}
		rest := strings.TrimPrefix(proposalName, prefix)
		for _, suffix := range knownSuffixes {
			if !strings.HasSuffix(rest, suffix) {
				continue
			}
			ownerName := strings.TrimSuffix(rest, suffix)
			if ownerName == "" {
				continue
			}
			return securityv1alpha1.WorkloadRef{
				Namespace: namespace,
				OwnerKind: kind,
				OwnerName: ownerName,
			}, true
		}
	}
	return securityv1alpha1.WorkloadRef{}, false
}

// reconcileOwnership ensures the proposal has a valid controller ownerReference.
// It deletes orphaned proposals whose owner workload no longer exists, and
// repairs a missing or incorrect ownerReference otherwise.
// It returns (true, nil) when the proposal was deleted.
func (r *WorkloadNetworkPolicyProposalReconciler) reconcileOwnership(
	ctx context.Context,
	proposal *securityv1alpha1.WorkloadNetworkPolicyProposal,
) (bool, error) {
	logger := log.FromContext(ctx)

	wk, ok := ownerRefFromProposalName(proposal.Namespace, proposal.Name)
	if !ok {
		return false, nil
	}
	owner := workload.OwnerObjectFor(wk.OwnerKind)
	if owner == nil {
		return false, nil
	}
	key := client.ObjectKey{Namespace: wk.Namespace, Name: wk.OwnerName}
	if err := r.Get(ctx, key, owner); err != nil {
		if !apierrors.IsNotFound(err) {
			return false, fmt.Errorf("getting owner %s %s: %w", wk.OwnerKind, key, err)
		}
		logger.Info("Deleting orphaned WorkloadNetworkPolicyProposal because its workload is gone",
			"namespace", proposal.Namespace, "name", proposal.Name, "workload", key.String())
		if deleteErr := r.Delete(ctx, proposal); deleteErr != nil {
			return false, client.IgnoreNotFound(deleteErr)
		}
		return true, nil
	}

	if current := metav1.GetControllerOf(proposal); current != nil && current.UID == owner.GetUID() {
		return false, nil
	}

	patch := client.MergeFrom(proposal.DeepCopy())
	proposal.OwnerReferences = nil
	if err := controllerutil.SetControllerReference(owner, proposal, r.Scheme); err != nil {
		return false, fmt.Errorf("setting controller reference: %w", err)
	}
	logger.Info("Restored ownerReference on WorkloadNetworkPolicyProposal",
		"namespace", proposal.Namespace, "name", proposal.Name, "workload", key.String())
	if err := r.Patch(ctx, proposal, patch); err != nil {
		return false, fmt.Errorf("patching ownerReference: %w", err)
	}
	return false, nil
}
