package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
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
	"github.com/kubewarden/network-enforcer/internal/workload"
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
	// metrics counts unattributed violations and attribution disagreements;
	// nil disables counting.
	metrics *attributionMetrics
}

type WorkloadNetworkPolicyStatusSyncConfig struct {
	UpdateInterval time.Duration
	// EventLogger for OTLP policy_violation_acknowledged; nil = disabled.
	EventLogger     otellog.Logger
	ViolationBuffer *ringbuf.Buffer[violation.Observation]
	// MetricsRegisterer registers the violation attribution counters; nil
	// disables them.
	MetricsRegisterer prometheus.Registerer
}

func NewWorkloadNetworkPolicyStatusSync(
	c client.Client,
	config *WorkloadNetworkPolicyStatusSyncConfig,
) (*WorkloadNetworkPolicyStatusSync, error) {
	if config.UpdateInterval <= 0 {
		return nil, fmt.Errorf("invalid update interval: %v", config.UpdateInterval)
	}

	var m *attributionMetrics
	if config.MetricsRegisterer != nil {
		var err error
		if m, err = registerAttributionMetrics(config.MetricsRegisterer); err != nil {
			return nil, err
		}
	}

	return &WorkloadNetworkPolicyStatusSync{
		Client:          c,
		updateInterval:  config.UpdateInterval,
		eventLogger:     config.EventLogger,
		violationBuffer: config.ViolationBuffer,
		metrics:         m,
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
	// The buffer is drained even when no WNP exists so those observations are
	// counted as unattributed.
	observations := r.violationBuffer.Drain()
	violationsByWNP := r.correlateViolationsToWNPs(ctx, observations, ownedIndex, wnpByKey)

	if len(wnpByKey) == 0 {
		r.logger.V(loglevel.VerbosityDebug).Info("No WorkloadNetworkPolicies found, skipping status update")
		return nil
	}

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

// correlateViolationsToWNPs groups scraped observations by the WNP they are
// attributed to (see attributeViolation) and materialises the ViolationRecord
// (without the controller-assigned ID, which mergeScrapedViolations assigns).
// Unattributed observations are counted and dropped.
func (r *WorkloadNetworkPolicyStatusSync) correlateViolationsToWNPs(
	ctx context.Context,
	scraped []violation.Observation,
	ownedIndex map[types.NamespacedName]*types.NamespacedName,
	wnpByKey map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy,
) map[types.NamespacedName][]securityv1alpha1.ViolationRecord {
	result := make(map[types.NamespacedName][]securityv1alpha1.ViolationRecord)

	for _, obs := range scraped {
		wnpKey, reason := r.attributeViolation(ctx, obs, ownedIndex, wnpByKey)
		if reason != "" {
			r.metrics.recordUnattributed(obs, reason)
			r.logger.V(loglevel.VerbosityDebug).Info("Could not attribute violation to a WorkloadNetworkPolicy",
				"reason", reason,
				"direction", obs.Direction,
				"source", obs.Source,
				"destination", obs.Dest,
				"reportedPolicyNamespace", obs.DenyingPolicyNamespace,
				"reportedPolicyName", obs.DenyingPolicyName)
			continue
		}

		violationInfo := obs.ViolationInfo
		// The record always names the WNP it belongs to, which may differ from
		// the reported enforcing object (or be absent from the observation).
		violationInfo.DenyingPolicyNamespace = wnpKey.Namespace
		violationInfo.DenyingPolicyName = wnpKey.Name
		result[wnpKey] = append(result[wnpKey], securityv1alpha1.ViolationRecord{
			ViolationInfo: violationInfo,
		})
	}

	return result
}

// attributeViolation resolves the WorkloadNetworkPolicy an observation belongs
// to. It returns the WNP key and an empty reason on success, or the
// unattributed reason otherwise. The chain is:
//
//  1. The enforcing object reported by the data plane, when its owning WNP is
//     verified against the ownership index and targets the subject workload.
//  2. Otherwise, the WNP whose (targetRef, direction) matches the subject.
//  3. Otherwise, the violation is unattributed.
func (r *WorkloadNetworkPolicyStatusSync) attributeViolation(
	ctx context.Context,
	obs violation.Observation,
	ownedIndex map[types.NamespacedName]*types.NamespacedName,
	wnpByKey map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy,
) (types.NamespacedName, string) {
	subject, hasSubject := violationSubject(obs)

	if reportedWNP, ok := r.reportedOwningWNP(obs, ownedIndex, wnpByKey); ok && hasSubject {
		targetsSubject := reportedWNP.Namespace == subject.Namespace &&
			reportedWNP.Spec.TargetRef.Kind == subject.OwnerKind &&
			reportedWNP.Spec.TargetRef.Name == subject.OwnerName
		if !targetsSubject {
			r.metrics.recordDisagreement(obs)
			r.logger.Info("Reported policy is owned by a WorkloadNetworkPolicy targeting another workload, "+
				"attributing violation to the subject; pod selectors likely overlap",
				"reportedPolicyNamespace", obs.DenyingPolicyNamespace,
				"reportedPolicyName", obs.DenyingPolicyName,
				"owningPolicy", reportedWNP.NamespacedName().String(),
				"subject", subject)
		} else if reportedWNP.Spec.Direction == obs.Direction {
			return reportedWNP.NamespacedName(), ""
		}
	}

	if !hasSubject {
		return types.NamespacedName{}, unattributedReasonUnknownSubject
	}

	wnp, err := workload.LookupWNPByTarget(
		ctx, r.Client, subject.Namespace, subject.OwnerKind, subject.OwnerName, obs.Direction,
	)
	switch {
	case errors.Is(err, workload.ErrTargetNotFound):
		return types.NamespacedName{}, unattributedReasonNoTargetPolicy
	case errors.Is(err, workload.ErrDuplicateTarget):
		return types.NamespacedName{}, unattributedReasonDuplicateTargetPolicy
	case err != nil:
		r.logger.Error(err, "Failed to look up WorkloadNetworkPolicy by targetRef", "subject", subject)
		return types.NamespacedName{}, unattributedReasonLookupFailed
	}

	// The cache may already hold a WNP that is not in this cycle's snapshot.
	wnpKey := wnp.NamespacedName()
	if _, ok := wnpByKey[wnpKey]; !ok {
		return types.NamespacedName{}, unattributedReasonNoTargetPolicy
	}
	return wnpKey, ""
}

// violationSubject returns the workload the violated policy selects: the
// source for egress, the destination for ingress. It is never the peer, so an
// off-cluster egress destination does not prevent attribution. It reports false
// when the direction is unknown or the subject is not a supported workload.
func violationSubject(obs violation.Observation) (securityv1alpha1.WorkloadRef, bool) {
	var subject securityv1alpha1.WorkloadRef
	switch obs.Direction {
	case networkingv1.PolicyTypeEgress:
		subject = obs.Source
	case networkingv1.PolicyTypeIngress:
		subject = obs.Dest
	default:
		return securityv1alpha1.WorkloadRef{}, false
	}
	if subject.Namespace == "" || subject.OwnerName == "" || !subject.IsSupported() {
		return securityv1alpha1.WorkloadRef{}, false
	}
	return subject, true
}

// reportedOwningWNP returns the WNP owning the enforcing object reported in the
// observation, verified against the ownership index. A reported NetworkPolicy
// must be controlled by a known WNP; a reported object with no NetworkPolicy
// behind it (monitor mode deletes it, Istio renders an AuthorizationPolicy with
// the WNP name) is accepted when a WNP with that name exists.
func (r *WorkloadNetworkPolicyStatusSync) reportedOwningWNP(
	obs violation.Observation,
	ownedIndex map[types.NamespacedName]*types.NamespacedName,
	wnpByKey map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy,
) (*securityv1alpha1.WorkloadNetworkPolicy, bool) {
	if obs.DenyingPolicyName == "" {
		return nil, false
	}
	reported := types.NamespacedName{Namespace: obs.DenyingPolicyNamespace, Name: obs.DenyingPolicyName}

	if owner, found := ownedIndex[reported]; found && obs.Provider == securityv1alpha1.PolicyBackendKubernetes {
		if owner == nil {
			r.logger.V(loglevel.VerbosityDebug).Info(
				"Reported NetworkPolicy is not managed by a WorkloadNetworkPolicy",
				"reportedPolicy", reported.String())
			return nil, false
		}
		// findWNPOwnerRef only indexes owners present in wnpByKey.
		return wnpByKey[*owner], true
	}

	if wnp, ok := wnpByKey[reported]; ok {
		return wnp, true
	}
	r.logger.V(loglevel.VerbosityDebug).Info(
		"Reported policy is not managed by a WorkloadNetworkPolicy",
		"reportedPolicy", reported.String())
	return nil, false
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
