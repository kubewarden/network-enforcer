package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/source"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/ringbuf"
	"github.com/kubewarden/network-enforcer/internal/types"
	"github.com/kubewarden/network-enforcer/internal/violation"
	"github.com/kubewarden/network-enforcer/internal/workload"
)

const (
	// DefaultEventChannelBufferSize defines the channel buffer size used to
	// deliver events to learning_controller.
	// This is a arbitrary number right now and can be fine-tuned or made configurable in the future.
	defaultEventChannelBufferSize = 4096
)

type LearningReconciler struct {
	client.Client

	Scheme          *runtime.Scheme
	eventChan       chan event.TypedGenericEvent[types.LearningEvent]
	violationBuffer *ringbuf.Buffer[violation.Observation]
}

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets,verbs=get;list;watch
// +kubebuilder:rbac:groups=networkenforcer.kubewarden.io,resources=workloadnetworkpolicyproposals,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=networkenforcer.kubewarden.io,resources=workloadnetworkpolicies,verbs=get;list;watch

func NewLearningReconciler(
	client client.Client,
	scheme *runtime.Scheme,
	violationBuffer *ringbuf.Buffer[violation.Observation],
) *LearningReconciler {
	return &LearningReconciler{
		Client: client,
		Scheme: scheme,
		eventChan: make(
			chan event.TypedGenericEvent[types.LearningEvent],
			defaultEventChannelBufferSize,
		),
		violationBuffer: violationBuffer,
	}
}

func (r *LearningReconciler) setOwnerReference(
	ctx context.Context,
	proposal *securityv1alpha1.WorkloadNetworkPolicyProposal,
	wk *securityv1alpha1.WorkloadRef,
) error {
	if metav1.GetControllerOf(proposal) != nil {
		return nil
	}
	owner := workload.OwnerObjectFor(wk.OwnerKind)
	if owner == nil {
		return fmt.Errorf("unsupported workload kind: %s", wk.OwnerKind)
	}
	key := client.ObjectKey{Namespace: wk.Namespace, Name: wk.OwnerName}
	if err := r.Get(ctx, key, owner); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("owning workload not found: %s %s", wk.OwnerKind, key)
		}
		return fmt.Errorf("getting owner %s %s: %w", wk.OwnerKind, key, err)
	}
	if err := controllerutil.SetControllerReference(owner, proposal, r.Scheme); err != nil {
		return fmt.Errorf("setting controller reference on proposal %s: %w", client.ObjectKeyFromObject(proposal), err)
	}
	return nil
}

func (r *LearningReconciler) GetEnqueueFunc() func(types.LearningEvent) bool {
	return r.enqueueEvent
}

func (r *LearningReconciler) enqueueEvent(evt types.LearningEvent) bool {
	select {
	case r.eventChan <- event.TypedGenericEvent[types.LearningEvent]{Object: evt}:
		return true
	default:
		return false
	}
}

// Reconcile maintains a retry mechanism with exponential backoff when processing learning events.
func (r *LearningReconciler) Reconcile(
	ctx context.Context,
	req types.LearningEvent,
) (ctrl.Result, error) {
	if req.Backend == securityv1alpha1.PolicyBackendIstio {
		return ctrl.Result{}, r.processIstioLearningEvent(ctx, req)
	}
	return ctrl.Result{}, r.processKubernetesLearningEvent(ctx, req)
}

type ProcessEventHandler struct {
}

func (e ProcessEventHandler) Create(
	_ context.Context,
	_ event.TypedCreateEvent[types.LearningEvent],
	_ workqueue.TypedRateLimitingInterface[types.LearningEvent],
) {

}

func (e ProcessEventHandler) Update(
	_ context.Context,
	_ event.TypedUpdateEvent[types.LearningEvent],
	_ workqueue.TypedRateLimitingInterface[types.LearningEvent],
) {

}

func (e ProcessEventHandler) Delete(
	_ context.Context,
	_ event.TypedDeleteEvent[types.LearningEvent],
	_ workqueue.TypedRateLimitingInterface[types.LearningEvent],
) {

}

func (e ProcessEventHandler) Generic(
	_ context.Context,
	evt event.TypedGenericEvent[types.LearningEvent],
	q workqueue.TypedRateLimitingInterface[types.LearningEvent],
) {
	q.AddRateLimited(evt.Object)
}

// SetupWithManager sets up the controller with the Manager.
func (r *LearningReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return builder.TypedControllerManagedBy[types.LearningEvent](mgr).
		Named("learningController").
		WatchesRawSource(
			source.TypedChannel(
				r.eventChan,
				&ProcessEventHandler{},
			),
		).
		Complete(r)
}
