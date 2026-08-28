package scraper

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/istio"
	"github.com/rancher-sandbox/network-enforcer/internal/ringbuf"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/rancher-sandbox/network-enforcer/internal/violation"
	otellog "go.opentelemetry.io/otel/log"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

const gracefulGRPCTimeout = 5 * time.Second

type LearningEnqueueFunc func(types.LearningEvent) bool

const (
	// keys.
	eventTypeKey         = "evt.type"
	srcIdentityKey       = "src.identity"
	dstNamespaceKey      = "dst.namespace"
	dstNameKey           = "dst.name"
	dstPortKey           = "dst.port"
	bodyKey              = "body"
	policyKey            = "policy"
	dstNamespacedNameKey = "dst.namespaced_name"
	srcAddrKey           = "src.addr"

	eventTypeLearn   = "learn"
	eventTypeMonitor = "monitor"
	eventTypeProtect = "protect"

	spiffeURIPrefix = "spiffe://"
)

// IstioScraperConfig configures IstioScraper.
type IstioScraperConfig struct {
	ViolationBuffer      *ringbuf.Buffer[violation.Observation]
	EnqueueLearningEvent LearningEnqueueFunc
	Logger               *slog.Logger
	ViolationOtelLogger  otellog.Logger
	OtelPort             int
	Enricher             *istio.Enricher
	FlowDumperBuffer     *ringbuf.Buffer[json.RawMessage]
}

// IstioScraper receives OTLP log events from istio-watchers.
type IstioScraper struct {
	collogspb.UnimplementedLogsServiceServer
	IstioScraperConfig
}

// NewIstioScraper creates an OTLP log scraper for Istio.
func NewIstioScraper(
	conf IstioScraperConfig,
) *IstioScraper {
	return &IstioScraper{
		IstioScraperConfig: conf,
	}
}

func (s *IstioScraper) Start(ctx context.Context) error {
	defer func() {
		s.Logger.InfoContext(ctx, "istio scraper has stopped")
	}()
	lc := net.ListenConfig{}
	addr := fmt.Sprintf(":%d", s.OtelPort)
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	var opts []grpc.ServerOption
	s.Logger.InfoContext(ctx, "OTLP Istio scraper running in insecure mode")

	grpcServer := grpc.NewServer(opts...)
	collogspb.RegisterLogsServiceServer(grpcServer, s)
	s.Logger.InfoContext(ctx, "Starting OTLP logs server", "addr", addr)

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- grpcServer.Serve(listener)
	}()

	select {
	case err = <-serveErrCh:
		if err != nil {
			return fmt.Errorf("gRPC server.Serve error: %w", err)
		}
		return nil

	case <-ctx.Done():
		done := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(done)
		}()

		select {
		case <-done:
			// graceful stop completed
		case <-time.After(gracefulGRPCTimeout):
			s.Logger.WarnContext(ctx, "GracefulStop timed out; forcing Stop()", "timeout", gracefulGRPCTimeout.String())
			grpcServer.Stop()
		}

		// wait for Serve to return (usually immediate after Stop/GracefulStop)
		err = <-serveErrCh
		if err != nil {
			return fmt.Errorf("gRPC server.Serve error: %w", err)
		}
		return nil
	}
}

func (s *IstioScraper) Export(
	ctx context.Context,
	req *collogspb.ExportLogsServiceRequest,
) (*collogspb.ExportLogsServiceResponse, error) {
	// todo!: evaluate if this is the correct way to extract logs, this is AI-generated.
	for _, resourceLogs := range req.GetResourceLogs() {
		resourceAttrs := attrMap(resourceLogs.GetResource().GetAttributes())
		for _, scopeLogs := range resourceLogs.GetScopeLogs() {
			for _, record := range scopeLogs.GetLogRecords() {
				attrs := mergeAttrMaps(resourceAttrs, attrMap(record.GetAttributes()))
				s.Logger.DebugContext(ctx, "Received OTLP log record", "attrs", attrs)
				dumpFlow(ctx, s.Logger, s.FlowDumperBuffer, record)
				switch attrs[eventTypeKey] {
				case eventTypeLearn:
					s.enqueueLearningEvent(ctx, attrs)
				case eventTypeMonitor, eventTypeProtect:
					// monitor and violation records share the same plumbing: they are
					// both routed through the violation path, differing only in the
					// enforcement action (monitor dry-run vs protect enforcement).
					s.recordPolicyEvent(ctx, record, attrs)
				default:
					s.Logger.WarnContext(ctx, "Skipping OTLP log record with unexpected event type",
						eventTypeKey, attrs[eventTypeKey], "attrs", attrs)
				}
			}
		}
	}

	return &collogspb.ExportLogsServiceResponse{}, nil
}

// enqueueLearningEvent feeds a `learn` record into the learning pipeline.
func (s *IstioScraper) enqueueLearningEvent(ctx context.Context, attrs map[string]string) {
	dstPodName := attrs[dstNameKey]
	dstNamespace := attrs[dstNamespaceKey]
	dstPortAttr := attrs[dstPortKey]
	// Strip the `spiffe://` scheme as soon as we ingest the identity: the
	// canonical principal form (Istio convention and our stored
	// WorkloadRef.Identity) carries no prefix.
	srcIdentity, hasSPIFFEPrefix := strings.CutPrefix(attrs[srcIdentityKey], spiffeURIPrefix)
	if dstPodName == "" || dstNamespace == "" || dstPortAttr == "" || !hasSPIFFEPrefix || srcIdentity == "" {
		s.Logger.WarnContext(ctx, "Skipping learning event with missing required fields",
			dstNameKey, dstPodName,
			dstNamespaceKey, dstNamespace,
			dstPortKey, dstPortAttr,
			srcIdentityKey, attrs[srcIdentityKey],
			"attrs", attrs,
		)
		return
	}

	dstPort, err := parsePort(dstPortAttr)
	if err != nil {
		s.Logger.WarnContext(ctx, "Failed to parse destination port", "dstPort", dstPortAttr, "error", err)
		return
	}

	if s.Enricher == nil {
		s.Logger.ErrorContext(ctx, "cannot send learning events without enricher")
		return
	}

	dstWorkloadRef, err := s.Enricher.GetWorkloadRef(ctx,
		k8stypes.NamespacedName{Namespace: dstNamespace, Name: dstPodName})
	if err != nil {
		s.Logger.WarnContext(ctx, "Failed to get destination workload reference", "error", err)
		return
	}

	// If the destination type is not supported we don't even send the event to the channel
	if !dstWorkloadRef.IsSupported() {
		s.Logger.DebugContext(ctx,
			"Skipping learning event with unsupported destination workload",
			"dstWorkloadRef", dstWorkloadRef,
		)
		return
	}

	// Generate Istio Learning Event:
	// - for the source, the identity is enough, we don't need the workload name or labels.
	// - for the destination, we need the workload name and labels but not the identity.
	learningEvent := types.LearningEvent{
		Source:   &securityv1alpha1.WorkloadRef{Identity: srcIdentity},
		Dest:     &dstWorkloadRef,
		DstPort:  dstPort,
		Protocol: corev1.ProtocolTCP, // the protocol is always TCP for Istio.
		Backend:  securityv1alpha1.PolicyBackendIstio,
	}
	if !s.EnqueueLearningEvent(learningEvent) {
		// todo!: we can consider some rate limiting here
		s.Logger.WarnContext(ctx, "Failed to enqueue learning event, channel is full")
	}
}

// recordPolicyEvent routes a `monitor` or `violation` record through the
// shared violation path: it normalises the OTLP attributes into a
// violation.Observation, emits it as an OTel `policy_violation_observed` log
// (no-op when the logger is nil) and records it into the shared violation
// buffer consumed by the controller.
func (s *IstioScraper) recordPolicyEvent(
	ctx context.Context,
	rec *logspb.LogRecord,
	attrs map[string]string,
) {
	observation := policyEventToObservation(rec, attrs)

	// Enrich the observation (source peer IP / destination pod name -> owning
	// workload + SPIFFE identity) once here, so both the OTel stream and the
	// buffered record consumed by the controller carry the attribution. A nil
	// Enricher is a no-op passthrough.
	observation = s.Enricher.Enrich(ctx, s.Logger, observation)

	violation.EmitOtelLog(ctx, s.ViolationOtelLogger, observation)

	if dropped := s.ViolationBuffer.Record(observation); dropped {
		s.Logger.WarnContext(ctx, "Violation buffer is full, dropped the oldest violation")
	}
}

// policyEventToObservation converts the OTLP attributes of a `monitor` or
// `violation` record into the provider-neutral in-flight representation.
// These records are produced on the destination ztunnel for inbound
// connections, so the direction is always ingress and the destination is the
// workload written in `dst.namespaced_name`. The source is only known by its
// address (`ip:port`), not by workload identity.
func policyEventToObservation(
	rec *logspb.LogRecord,
	attrs map[string]string,
) violation.Observation {
	dstNamespace, dstName := splitNamespacedName(attrs[dstNamespacedNameKey])
	policyNamespace, policyName := splitNamespacedName(attrs[policyKey])

	action := securityv1alpha1.WorkloadNetworkPolicyModeProtect
	if attrs[eventTypeKey] == eventTypeMonitor {
		action = securityv1alpha1.WorkloadNetworkPolicyModeMonitor
	}

	return violation.Observation{
		Provider: securityv1alpha1.PolicyBackendIstio,
		ViolationInfo: securityv1alpha1.ViolationInfo{
			Timestamp:              timestampFromRecord(rec),
			Source:                 securityv1alpha1.WorkloadRef{OwnerName: attrs[srcAddrKey]},
			Dest:                   securityv1alpha1.WorkloadRef{Namespace: dstNamespace, OwnerName: dstName},
			Protocol:               corev1.ProtocolTCP,
			Action:                 action,
			DenyingPolicyNamespace: policyNamespace,
			DenyingPolicyName:      policyName,
		},
	}
}

// timestampFromRecord returns the record timestamp, falling back to now when
// the OTLP record does not carry one or it is out of the int64 range.
func timestampFromRecord(rec *logspb.LogRecord) metav1.Time {
	nano := rec.GetTimeUnixNano()
	if nano > 0 && nano <= math.MaxInt64 {
		return metav1.NewTime(time.Unix(0, int64(nano)))
	}
	return metav1.NewTime(time.Now())
}

// splitNamespacedName splits a `namespace/name` string into its two parts,
// returning ("", value) when the separator is missing.
func splitNamespacedName(namespacedName string) (string, string) {
	namespace, name, found := strings.Cut(namespacedName, "/")
	if !found {
		return "", namespacedName
	}
	return namespace, name
}

func mergeAttrMaps(base, override map[string]string) map[string]string {
	merged := make(map[string]string, len(base)+len(override))
	maps.Copy(merged, base)
	maps.Copy(merged, override)
	return merged
}

func attrMap(attrs []*commonpb.KeyValue) map[string]string {
	m := make(map[string]string, len(attrs))
	for _, kv := range attrs {
		value := anyValueToString(kv.GetValue())
		if value == "" {
			continue
		}
		m[kv.GetKey()] = value
	}
	return m
}

func anyValueToString(value *commonpb.AnyValue) string {
	if value == nil {
		return ""
	}

	switch v := value.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return v.StringValue
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(v.IntValue, 10)
	case *commonpb.AnyValue_DoubleValue:
		return strconv.FormatFloat(v.DoubleValue, 'f', -1, 64)
	case *commonpb.AnyValue_BoolValue:
		return strconv.FormatBool(v.BoolValue)
	default:
		return ""
	}
}
