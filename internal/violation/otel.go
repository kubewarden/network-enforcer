package violation

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
)

// eventNameViolationObserved is the OTel log event name for a raw, un-attributed
// violation observation. Full fidelity lives here (not in status): the
// observation is emitted even when it matches no WorkloadNetworkPolicy.
const eventNameViolationObserved = "policy_violation_observed"

// Stable OTel attribute schema for violation observations. Producers must not
// rename these; consumers (collectors, dashboards) rely on them.
const (
	otelAttrEnforcementProvider = "enforcement.provider"
	otelAttrAction              = "action"

	otelAttrSrcName      = "source.workload.name"
	otelAttrSrcNamespace = "source.workload.namespace"
	otelAttrSrcKind      = "source.workload.kind"
	otelAttrSrcIdentity  = "source.workload.identity"

	otelAttrDstName      = "destination.workload.name"
	otelAttrDstNamespace = "destination.workload.namespace"
	otelAttrDstKind      = "destination.workload.kind"
	otelAttrDstIdentity  = "destination.workload.identity"

	otelAttrTransport = "network.transport"
	otelAttrDstPort   = "destination.port"

	otelAttrPolicyNamespace = "policy.ref.namespace"
	otelAttrPolicyName      = "policy.ref.name"
)

// OtelAttributeKeys returns every attribute key of the stable schema above.
func OtelAttributeKeys() []string {
	return []string{
		otelAttrEnforcementProvider,
		otelAttrAction,
		otelAttrSrcName,
		otelAttrSrcNamespace,
		otelAttrSrcKind,
		otelAttrSrcIdentity,
		otelAttrDstName,
		otelAttrDstNamespace,
		otelAttrDstKind,
		otelAttrDstIdentity,
		otelAttrTransport,
		otelAttrDstPort,
		otelAttrPolicyNamespace,
		otelAttrPolicyName,
	}
}

// EmitOtelLog emits the observation to the OTel log logger with the stable
// attribute schema. It is a no-op when logger is nil (OTLP disabled).
func EmitOtelLog(ctx context.Context, logger otellog.Logger, observation Observation) {
	if logger == nil {
		return
	}

	var rec otellog.Record
	rec.SetEventName(eventNameViolationObserved)
	rec.SetSeverity(otellog.SeverityWarn)
	rec.SetTimestamp(observation.Timestamp.Time)

	// Empty string attributes are skipped so the OTel export never carries
	// empty kind/identity placeholders (the istio producer does not know the
	// owner kind of a workload).
	addStringAttrs(&rec, otelAttrEnforcementProvider, string(observation.Provider))
	addStringAttrs(&rec, otelAttrAction, string(observation.Action))

	addStringAttrs(&rec, otelAttrSrcName, observation.Source.OwnerName)
	addStringAttrs(&rec, otelAttrSrcNamespace, observation.Source.Namespace)
	addStringAttrs(&rec, otelAttrSrcKind, string(observation.Source.OwnerKind))
	addStringAttrs(&rec, otelAttrSrcIdentity, observation.Source.Identity)

	addStringAttrs(&rec, otelAttrDstName, observation.Dest.OwnerName)
	addStringAttrs(&rec, otelAttrDstNamespace, observation.Dest.Namespace)
	addStringAttrs(&rec, otelAttrDstKind, string(observation.Dest.OwnerKind))
	addStringAttrs(&rec, otelAttrDstIdentity, observation.Dest.Identity)

	addStringAttrs(&rec, otelAttrTransport, string(observation.Protocol))

	addStringAttrs(&rec, otelAttrPolicyNamespace, observation.DenyingPolicyNamespace)
	addStringAttrs(&rec, otelAttrPolicyName, observation.DenyingPolicyName)

	rec.AddAttributes(attribute.Int64(otelAttrDstPort, int64(observation.DstPort)))

	logger.Emit(ctx, rec)
}

// addStringAttrs adds a string attribute to the record when the value is
// non-empty, so the OTel export never carries empty placeholders. The single
// (key, value) prototype keeps every attribute explicit: pairs cannot be
// accidentally dropped or misaligned.
func addStringAttrs(rec *otellog.Record, key, value string) {
	if value != "" {
		rec.AddAttributes(attribute.String(key, value))
	}
}
