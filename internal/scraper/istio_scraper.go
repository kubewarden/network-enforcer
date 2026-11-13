package scraper

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	otellog "go.opentelemetry.io/otel/log"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"

	agentv1 "github.com/kubewarden/network-enforcer/proto/agent/v1"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/istio"
	"github.com/kubewarden/network-enforcer/internal/ringbuf"
	"github.com/kubewarden/network-enforcer/internal/types"
	"github.com/kubewarden/network-enforcer/internal/violation"
)

type LearningEnqueueFunc func(types.LearningEvent) bool

const (
	// Keys retained for the ztunnel Lua parity fixtures.
	eventTypeKey         = "evt.type"
	srcIdentityKey       = "src.identity"
	dstNamespaceKey      = "dst.namespace"
	dstNameKey           = "dst.name"
	dstPortKey           = "dst.port"
	messageKey           = "message"
	policyKey            = "policy"
	dstNamespacedNameKey = "dst.namespaced_name"
	srcAddrKey           = "src.addr"

	spiffeURIPrefix = "spiffe://"
)

// IstioScraperConfig configures typed events pulled from discovered agents.
type IstioScraperConfig struct {
	ViolationBuffer      *ringbuf.Buffer[violation.Observation]
	EnqueueLearningEvent LearningEnqueueFunc
	Logger               *slog.Logger
	ViolationOtelLogger  otellog.Logger
	Enricher             *istio.Enricher
	FlowDumperBuffer     *ringbuf.Buffer[json.RawMessage]
}

// IstioScraper converts agent events into the existing learning and policy pipelines.
type IstioScraper struct {
	IstioScraperConfig

	pull   IstioPullConfig
	jitter func(time.Duration, float64) time.Duration
	wait   func(context.Context, time.Duration) bool
}

// NewIstioScraper creates a scraper for typed Istio agent events.
func NewIstioScraper(conf IstioScraperConfig) *IstioScraper {
	if conf.Logger == nil {
		conf.Logger = slog.Default()
	}
	return &IstioScraper{
		IstioScraperConfig: conf,
		jitter:             randomDelay,
		wait:               waitForDelay,
	}
}

func (s *IstioScraper) processEvent(ctx context.Context, event *agentv1.Event) {
	if event == nil {
		s.Logger.WarnContext(ctx, "Skipping nil Istio agent event")
		return
	}

	// A malformed debug payload must not interfere with processing the typed event.
	if raw := event.GetRawRecord(); len(raw) != 0 {
		dumpFlow(ctx, s.Logger, s.FlowDumperBuffer, json.RawMessage(raw))
	}

	switch kind := event.GetKind().(type) {
	case *agentv1.Event_Learn:
		if kind.Learn == nil {
			s.Logger.WarnContext(ctx, "Skipping Istio learning event with empty payload")
			return
		}
		s.enqueueLearningEvent(ctx, kind.Learn)
	case *agentv1.Event_Policy:
		if kind.Policy == nil {
			s.Logger.WarnContext(ctx, "Skipping Istio policy event with empty payload")
			return
		}
		if kind.Policy.GetMode() != agentv1.PolicyMode_POLICY_MODE_MONITOR &&
			kind.Policy.GetMode() != agentv1.PolicyMode_POLICY_MODE_PROTECT {
			s.Logger.WarnContext(ctx, "Skipping Istio policy event with unknown mode", "mode", kind.Policy.GetMode())
			return
		}
		s.recordPolicyEvent(ctx, event, kind.Policy)
	default:
		s.Logger.WarnContext(ctx, "Skipping Istio agent event with unknown kind")
	}
}

func (s *IstioScraper) enqueueLearningEvent(ctx context.Context, event *agentv1.LearnEvent) {
	dstPodName := event.GetDestinationName()
	dstNamespace := event.GetDestinationNamespace()
	dstPortAttr := event.GetDestinationPort()
	srcIdentity, hasSPIFFEPrefix := strings.CutPrefix(event.GetSourceIdentity(), spiffeURIPrefix)
	if dstPodName == "" || dstNamespace == "" || dstPortAttr == "" || !hasSPIFFEPrefix || srcIdentity == "" {
		s.Logger.WarnContext(ctx, "Skipping learning event with missing required fields",
			dstNameKey, dstPodName,
			dstNamespaceKey, dstNamespace,
			dstPortKey, dstPortAttr,
			srcIdentityKey, event.GetSourceIdentity(),
		)
		return
	}

	dstPort, err := parsePort(dstPortAttr)
	if err != nil {
		s.Logger.WarnContext(ctx, "Failed to parse destination port", "dstPort", dstPortAttr, "error", err)
		return
	}
	if s.Enricher == nil {
		s.Logger.ErrorContext(ctx, "Cannot send learning events without enricher")
		return
	}

	dstWorkloadRef, err := s.Enricher.GetWorkloadRef(ctx,
		k8stypes.NamespacedName{Namespace: dstNamespace, Name: dstPodName})
	if err != nil {
		s.Logger.WarnContext(ctx, "Failed to get destination workload reference", "error", err)
		return
	}
	if !dstWorkloadRef.IsSupported() {
		s.Logger.DebugContext(ctx, "Skipping learning event with unsupported destination workload",
			"dstWorkloadRef", dstWorkloadRef)
		return
	}

	learningEvent := types.LearningEvent{
		Source:   &securityv1alpha1.WorkloadRef{Identity: srcIdentity},
		Dest:     &dstWorkloadRef,
		DstPort:  dstPort,
		Protocol: corev1.ProtocolTCP,
		Backend:  securityv1alpha1.PolicyBackendIstio,
	}
	if s.EnqueueLearningEvent == nil || !s.EnqueueLearningEvent(learningEvent) {
		s.Logger.WarnContext(ctx, "Failed to enqueue learning event, channel is full")
	}
}

func (s *IstioScraper) recordPolicyEvent(ctx context.Context, event *agentv1.Event, policy *agentv1.PolicyEvent) {
	observation := policyEventToObservation(event, policy)
	if s.Enricher != nil {
		observation = s.Enricher.Enrich(ctx, s.Logger, observation)
	}
	violation.EmitOtelLog(ctx, s.ViolationOtelLogger, observation)
	if s.ViolationBuffer != nil {
		if dropped := s.ViolationBuffer.Record(observation); dropped {
			s.Logger.WarnContext(ctx, "Violation buffer is full, dropped the oldest violation")
		}
	}
}

func policyEventToObservation(event *agentv1.Event, policy *agentv1.PolicyEvent) violation.Observation {
	dstNamespace, dstName := splitNamespacedName(policy.GetDestinationNamespacedName())
	policyNamespace, policyName := splitNamespacedName(policy.GetPolicy())
	action := securityv1alpha1.WorkloadNetworkPolicyModeProtect
	if policy.GetMode() == agentv1.PolicyMode_POLICY_MODE_MONITOR {
		action = securityv1alpha1.WorkloadNetworkPolicyModeMonitor
	}
	return violation.Observation{
		Provider:               securityv1alpha1.PolicyBackendIstio,
		Direction:              networkingv1.PolicyTypeIngress,
		Timestamp:              timestampFromEvent(event),
		Source:                 securityv1alpha1.WorkloadRef{OwnerName: policy.GetSourceAddress()},
		Dest:                   securityv1alpha1.WorkloadRef{Namespace: dstNamespace, OwnerName: dstName},
		Protocol:               corev1.ProtocolTCP,
		Action:                 action,
		DenyingPolicyNamespace: policyNamespace,
		DenyingPolicyName:      policyName,
	}
}

// timestampFromEvent preserves valid timestamps, including the Unix epoch, and falls back when absent/invalid.
func timestampFromEvent(event *agentv1.Event) metav1.Time {
	observedAt := event.GetObservedAt()
	if observedAt != nil && observedAt.CheckValid() == nil {
		return metav1.NewTime(observedAt.AsTime())
	}
	return metav1.NewTime(time.Now())
}

func splitNamespacedName(namespacedName string) (string, string) {
	namespace, name, found := strings.Cut(namespacedName, "/")
	if !found {
		return "", namespacedName
	}
	return namespace, name
}
