package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/ringbuf"
	"github.com/kubewarden/network-enforcer/internal/types/loglevel"
	"github.com/kubewarden/network-enforcer/internal/violation"
)

const eventNamePolicyViolationAcknowledged = "policy_violation_acknowledged"

// +kubebuilder:rbac:groups=networkenforcer.kubewarden.io,resources=workloadnetworkpolicies/status,verbs=get;patch;update

// WorkloadNetworkPolicyStatusSync drains buffered violation observations, correlates denies
// to the owning WNP, and writes status/annotations via two-phase patch.
// When eventLogger is set it emits policy_violation_acknowledged after a
// successful status patch (ordering guard, no duplicate logs on retry).
type WorkloadNetworkPolicyStatusSync struct {
	client.Client

	updateInterval  time.Duration
	eventLogger     otellog.Logger
	logger          logr.Logger
	violationBuffer *ringbuf.Buffer[violation.Observation]
}

type WorkloadNetworkPolicyStatusSyncConfig struct {
	UpdateInterval time.Duration
	// EventLogger for OTLP policy_violation_acknowledged; nil = disabled.
	EventLogger     otellog.Logger
	ViolationBuffer *ringbuf.Buffer[violation.Observation]
}

func NewWorkloadNetworkPolicyStatusSync(
	c client.Client,
	config *WorkloadNetworkPolicyStatusSyncConfig,
) (*WorkloadNetworkPolicyStatusSync, error) {
	if config.UpdateInterval <= 0 {
		return nil, fmt.Errorf("invalid update interval: %v", config.UpdateInterval)
	}

	return &WorkloadNetworkPolicyStatusSync{
		Client:          c,
		updateInterval:  config.UpdateInterval,
		eventLogger:     config.EventLogger,
		violationBuffer: config.ViolationBuffer,
	}, nil
}

// Start implements manager.Runnable. Runs the periodic sync loop.
func (r *WorkloadNetworkPolicyStatusSync) Start(ctx context.Context) error {
	r.logger = log.FromContext(ctx).WithName("WorkloadNetworkPolicyStatusSync")
	interval := r.updateInterval
	r.logger.Info("Starting with", "interval", interval.String())

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("Closing")
			return nil
		case <-time.After(interval):
			if err := r.sync(ctx); err != nil {
				r.logger.Error(err, "Failed to sync")
			}
		}
	}
}

// sync runs one cycle: discover agents, scrape, correlate, patch.
func (r *WorkloadNetworkPolicyStatusSync) sync(ctx context.Context) error {
	var wnpList securityv1alpha1.WorkloadNetworkPolicyList
	if err := r.List(ctx, &wnpList); err != nil {
		return fmt.Errorf("failed to list WorkloadNetworkPolicies: %w", err)
	}
	if len(wnpList.Items) == 0 {
		r.logger.V(loglevel.VerbosityDebug).Info("No WorkloadNetworkPolicies found, skipping sync")
		return nil
	}

	// Build index of WNP by NamespacedName for quick lookup.
	wnpByKey := make(map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy, len(wnpList.Items))
	for i := range wnpList.Items {
		key := types.NamespacedName{Namespace: wnpList.Items[i].Namespace, Name: wnpList.Items[i].Name}
		wnpByKey[key] = &wnpList.Items[i]
	}

	// Build ownership index: NetworkPolicy key -> owning WNP key.
	ownedIndex, err := r.buildOwnershipIndex(ctx, wnpByKey)
	if err != nil {
		return fmt.Errorf("failed to build ownership index: %w", err)
	}

	// Group scraped observations by the owning WNP. Observations are already
	// enriched at scrape time (source/dest workload + SPIFFE identity), so the
	// controller only correlates them here; it no longer resolves workloads.
	observations := r.violationBuffer.Drain()
	violationsByWNP := r.correlateViolationsToWNPs(observations, ownedIndex, wnpByKey)

	// Process every WNP: those with scraped violations get them merged;
	// those without still get clearAllowedViolations + acknowledgeViolationsFromAnnotations.
	for key, wnp := range wnpByKey {
		if err = r.processWorkloadNetworkPolicy(ctx, wnp, violationsByWNP[key]); err != nil {
			r.logger.Error(err, "Failed to process WorkloadNetworkPolicy",
				"policy", key)
		}
	}

	return nil
}

// buildOwnershipIndex maps NetworkPolicy keys to their owning WNP key.
func (r *WorkloadNetworkPolicyStatusSync) buildOwnershipIndex(
	ctx context.Context,
	wnpByKey map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy,
) (map[types.NamespacedName]*types.NamespacedName, error) {
	var npList networkingv1.NetworkPolicyList
	if err := r.List(ctx, &npList); err != nil {
		return nil, fmt.Errorf("failed to list NetworkPolicies: %w", err)
	}

	apiVersion := securityv1alpha1.GroupVersion.String()
	wnpKind := "WorkloadNetworkPolicy"

	index := make(map[types.NamespacedName]*types.NamespacedName, len(npList.Items))
	for _, np := range npList.Items {
		npKey := types.NamespacedName{Namespace: np.Namespace, Name: np.Name}
		if wnpKey, ok := findWNPOwnerRef(
			np.OwnerReferences, np.Namespace, apiVersion, wnpKind, wnpByKey,
		); ok {
			index[npKey] = &wnpKey
		} else {
			// we store a nil pointer to indicate no owner
			index[npKey] = nil
		}
	}
	return index, nil
}

// findWNPOwnerRef returns the owning WNP NamespacedName from a
// NetworkPolicy's OwnerReferences that matches a known WNP.
func findWNPOwnerRef(
	refs []metav1.OwnerReference,
	namespace, apiVersion, kind string,
	wnpByKey map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy,
) (types.NamespacedName, bool) {
	for _, ref := range refs {
		if ref.Controller != nil && *ref.Controller &&
			ref.APIVersion == apiVersion &&
			ref.Kind == kind {
			wnpKey := types.NamespacedName{Namespace: namespace, Name: ref.Name}
			if _, ok := wnpByKey[wnpKey]; ok {
				return wnpKey, true
			}
		}
	}
	return types.NamespacedName{}, false
}

// correlateViolationsToWNPs groups scraped observations by the owning WNP.
// Observations arrive already enriched from the scraper: source/dest workload +
// SPIFFE identity, and the owning WNP written into DenyingPolicyNamespace/Name
// (for both DENY and ALLOW-miss). This only keys them to a WNP and materialises
// the ViolationRecord (without the controller-assigned ID, which
// mergeScrapedViolations assigns). Observations with no owning WNP are dropped;
// deleted denying NetPols log a warning.
func (r *WorkloadNetworkPolicyStatusSync) correlateViolationsToWNPs(
	scraped []violation.Observation,
	ownedIndex map[types.NamespacedName]*types.NamespacedName,
	wnpByKey map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy,
) map[types.NamespacedName][]securityv1alpha1.ViolationRecord {
	result := make(map[types.NamespacedName][]securityv1alpha1.ViolationRecord)

	for _, obs := range scraped {
		wnpKey, ok := r.wnpKeyForViolation(obs, wnpByKey)
		if !ok {
			continue
		}

		// In protect mode it is possible that a k8s network policy has the same name of one of our WNPs
		// but it is not owned by us. if it is the case we should already have some errors when we try
		// to create the WNPs but we check also here to avoid wrong violation assignment
		owner, ok := ownedIndex[wnpKey]
		if ok && owner == nil {
			// we have an error only in case of policy presence and without owner
			err := errors.New(
				"found a Network policy with same name of WNP but not managed by us, cannot register violation",
			)
			r.logger.Error(err, err.Error(), "denyingPolicy", wnpKey.String())
			continue
		}

		result[wnpKey] = append(result[wnpKey], securityv1alpha1.ViolationRecord{
			ViolationInfo: obs.ViolationInfo,
		})
	}

	return result
}

// wnpKeyForViolation resolves the owning WorkloadNetworkPolicy for a scraped
// observation and reports whether a match was found.
//
// Both DENY and ALLOW-miss observations carry the owning policy in
// DenyingPolicyNamespace/DenyingPolicyName by the time they reach the controller.
// An explicit DENY names the enforcing policy directly (for the Istio provider
// the AuthorizationPolicy shares the WNP name). An ALLOW-miss carries no denying
// policy on the wire, so the scraper pre-resolves its owning WNP by matching the
// destination pod's labels against WNP selectors and writes it into the same
// fields (see istio.Enricher). An empty name means the observation could not be
// correlated and is dropped.
func (r *WorkloadNetworkPolicyStatusSync) wnpKeyForViolation(
	obs violation.Observation,
	wnpByKey map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy,
) (types.NamespacedName, bool) {
	if obs.DenyingPolicyName == "" {
		// The scraper was not able to correlate the observation, we cannot do anything here.
		return types.NamespacedName{}, false
	}

	// the k8s network policy should have the same name of the
	// workload network policy.
	wnpKey := types.NamespacedName{
		Namespace: obs.DenyingPolicyNamespace,
		Name:      obs.DenyingPolicyName,
	}
	if _, ok := wnpByKey[wnpKey]; !ok {
		r.logger.Info(
			"Denying WorkloadNetworkPolicy not found; violation may be caused by a policy not managed by us",
			"denyingPolicy",
			wnpKey.String(),
		)
		return types.NamespacedName{}, false
	}
	return wnpKey, true
}

// processWorkloadNetworkPolicy patches status then annotations using a
// MergeFrom base. Acknowledged-violation OTLP logs are emitted only after
// the status patch succeeds (ordering guard — prevents duplicate logs on
// retry), matching the runtime-enforcer approach.
func (r *WorkloadNetworkPolicyStatusSync) processWorkloadNetworkPolicy(
	ctx context.Context,
	wnp *securityv1alpha1.WorkloadNetworkPolicy,
	violations []securityv1alpha1.ViolationRecord,
) error {
	now := metav1.NewTime(time.Now())

	patchBase := client.MergeFrom(wnp.DeepCopy())
	newPolicy := wnp.DeepCopy()

	acknowledged := newPolicy.RecomputeStatus(violations, now)

	r.logger.V(loglevel.VerbosityDebug).Info("Updating WorkloadNetworkPolicy status",
		"policy", wnp.NamespacedName(),
		"violations", len(violations),
		"acknowledged", len(acknowledged),
		"activeCount", newPolicy.Status.ActiveViolationCount)

	if err := r.Status().Patch(ctx, newPolicy.DeepCopy(), patchBase); err != nil {
		return fmt.Errorf("failed to patch WorkloadNetworkPolicy status for %s: %w",
			wnp.NamespacedName(), err)
	}

	r.emitAcknowledgedViolations(ctx, acknowledged)

	if err := r.Patch(ctx, newPolicy.DeepCopy(), patchBase); err != nil {
		return fmt.Errorf("failed to patch WorkloadNetworkPolicy annotations for %s: %w",
			wnp.NamespacedName(), err)
	}

	return nil
}

func (r *WorkloadNetworkPolicyStatusSync) emitAcknowledgedViolations(
	ctx context.Context,
	acknowledgements []securityv1alpha1.AcknowledgedViolationRecord,
) {
	for _, ack := range acknowledgements {
		r.emitAcknowledgedViolationOtelLog(ctx, ack)
	}
}

func (r *WorkloadNetworkPolicyStatusSync) emitAcknowledgedViolationOtelLog(
	ctx context.Context,
	ack securityv1alpha1.AcknowledgedViolationRecord,
) {
	violation := ack.Violation
	var rec otellog.Record
	rec.SetEventName(eventNamePolicyViolationAcknowledged)
	rec.SetSeverity(otellog.SeverityInfo)
	rec.SetBody(attribute.StringValue(eventNamePolicyViolationAcknowledged))
	rec.SetTimestamp(time.Now())
	rec.AddAttributes(
		attribute.Int64("id", violation.ID),
		attribute.String("timestamp", violation.Timestamp.UTC().Format(time.RFC3339)),
		attribute.String("reason", ack.Reason),
		attribute.String("source.namespace", violation.Source.Namespace),
		attribute.String("source.workload.kind", string(violation.Source.OwnerKind)),
		attribute.String("source.workload.name", violation.Source.OwnerName),
		attribute.String("source.workload.identity", violation.Source.Identity),
		attribute.String("dest.namespace", violation.Dest.Namespace),
		attribute.String("dest.workload.kind", string(violation.Dest.OwnerKind)),
		attribute.String("dest.workload.name", violation.Dest.OwnerName),
		attribute.String("dest.workload.identity", violation.Dest.Identity),
		attribute.String("protocol", string(violation.Protocol)),
		attribute.Int64("dstPort", int64(violation.DstPort)),
		attribute.String("action", string(violation.Action)),
		attribute.String("denyingPolicy.namespace", violation.DenyingPolicyNamespace),
		attribute.String("denyingPolicy.name", violation.DenyingPolicyName),
	)

	if r.eventLogger != nil {
		r.eventLogger.Emit(ctx, rec)
	}
}

var _ manager.Runnable = (*WorkloadNetworkPolicyStatusSync)(nil)
