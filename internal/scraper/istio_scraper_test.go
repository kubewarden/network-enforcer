package scraper

import (
	"context"
	"log/slog"
	"testing"
	"time"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/rancher-sandbox/network-enforcer/internal/violationbuf"
	"github.com/stretchr/testify/require"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/embedded"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

type fakeOtelEventLogger struct {
	embedded.Logger

	emitted []otellog.Record
}

func (f *fakeOtelEventLogger) Enabled(context.Context, otellog.EnabledParameters) bool { return true }

func (f *fakeOtelEventLogger) Emit(_ context.Context, rec otellog.Record) {
	f.emitted = append(f.emitted, rec.Clone())
}

func testScraper(
	enqueue LearningEnqueueFunc,
	buffer *violationbuf.Buffer,
	logger otellog.Logger,
) *IstioScraper {
	return NewIstioScraper(IstioScraperConfig{
		ViolationBuffer:      buffer,
		EnqueueLearningEvent: enqueue,
		ViolationOtelLogger:  logger,
		Logger:               slog.New(slog.DiscardHandler),
	})
}

// otlpRequest wraps the given log records into an ExportLogsServiceRequest.
func otlpRequest(records ...*logspb.LogRecord) *collogspb.ExportLogsServiceRequest {
	return &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{
			{
				ScopeLogs: []*logspb.ScopeLogs{
					{LogRecords: records},
				},
			},
		},
	}
}

func otlpRecord(attrs map[string]string, unixNano int64) *logspb.LogRecord {
	rec := &logspb.LogRecord{TimeUnixNano: uint64(unixNano)}
	for k, v := range attrs {
		rec.Attributes = append(rec.Attributes, &commonpb.KeyValue{
			Key: k,
			Value: &commonpb.AnyValue{
				Value: &commonpb.AnyValue_StringValue{StringValue: v},
			},
		})
	}
	return rec
}

func TestExportRoutesRecordsByEventType(t *testing.T) {
	t.Parallel()

	learned := make([]types.LearningEvent, 0)
	buffer := violationbuf.NewBuffer()
	otelLogger := &fakeOtelEventLogger{}

	scraper := testScraper(
		func(ev types.LearningEvent) bool {
			learned = append(learned, ev)
			return true
		},
		buffer,
		otelLogger,
	)

	req := otlpRequest(
		otlpRecord(map[string]string{
			eventTypeKey:    eventTypeLearn,
			dstNameKey:      "http-server-7bbf596dd9-4rgdc",
			dstNamespaceKey: "default",
			dstPortKey:      "18080",
			srcIdentityKey:  "spiffe://cluster.local/ns/default/sa/http-client-sa",
		}, 1),
		// monitor dry-run DENY with policy name
		otlpRecord(map[string]string{
			eventTypeKey:         eventTypeMonitor,
			dstNamespacedNameKey: "default/http-server-7bbf596dd9-8gs65",
			policyKey:            "default/deny-http-server-monitor",
			srcAddrKey:           "10.244.0.9:46266",
		}, 2),
		// violation explicit DENY with policy name
		otlpRecord(map[string]string{
			eventTypeKey:         eventTypeViolation,
			dstNamespacedNameKey: "default/http-server-6cbcc86f5d-lhq82",
			policyKey:            "default/deny-http-server-protect",
			srcAddrKey:           "10.244.0.5:49084",
		}, 3),
		// violation ALLOW-miss without policy name
		otlpRecord(map[string]string{
			eventTypeKey:         eventTypeViolation,
			dstNamespacedNameKey: "default/http-server-6cbcc86f5d-lhq82",
			srcAddrKey:           "10.244.0.5:52814",
		}, 4),
		// unknown event type must be skipped, not misrouted as learning
		otlpRecord(map[string]string{
			eventTypeKey: "something-else",
			dstNameKey:   "http-server",
		}, 5),
	)

	_, err := scraper.Export(context.Background(), req)
	require.NoError(t, err)

	// Only the `learn` record reaches the learning pipeline; the `spiffe://`
	// scheme is stripped at ingestion.
	require.Len(t, learned, 1)
	require.Equal(t, types.LearningEvent{
		DstName:      "http-server-7bbf596dd9-4rgdc",
		DstNamespace: "default",
		DstPort:      "18080",
		SrcIdentity:  "cluster.local/ns/default/sa/http-client-sa",
	}, learned[0])

	// The three policy records (monitor + 2 violations) reach the violation buffer.
	drained := buffer.Drain()
	require.Len(t, drained, 3)

	monitor := drained[2]
	require.Equal(t, networkingv1.PolicyTypeIngress, monitor.Direction)
	require.Equal(t, "default", monitor.DstNamespace)
	require.Equal(t, "http-server-7bbf596dd9-8gs65", monitor.DstName)
	require.Equal(t, corev1.ProtocolTCP, monitor.Protocol)
	require.Equal(t, "10.244.0.9:46266", monitor.SrcName)
	require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeMonitor, monitor.Action)
	require.Equal(t, "default", monitor.DenyingPolicyNamespace)
	require.Equal(t, "deny-http-server-monitor", monitor.DenyingPolicyName)

	deny := drained[1]
	require.Equal(t, "default", deny.DstNamespace)
	require.Equal(t, "http-server-6cbcc86f5d-lhq82", deny.DstName)
	require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeProtect, deny.Action)
	require.Equal(t, "default", deny.DenyingPolicyNamespace)
	require.Equal(t, "deny-http-server-protect", deny.DenyingPolicyName)

	allowMiss := drained[0]
	require.Equal(t, "http-server-6cbcc86f5d-lhq82", allowMiss.DstName)
	require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeProtect, allowMiss.Action)
	require.Empty(t, allowMiss.DenyingPolicyNamespace)
	require.Empty(t, allowMiss.DenyingPolicyName)

	// The `policy_violation_observed` OTel log is emitted for monitor and
	// violation records alike (3 records, one per policy event).
	require.Len(t, otelLogger.emitted, 3)
}

func TestPolicyEventToObservation(t *testing.T) {
	t.Parallel()

	unixNano := time.Date(2026, 8, 3, 15, 39, 7, 0, time.UTC).UnixNano()

	attrs := map[string]string{
		eventTypeKey:         eventTypeViolation,
		dstNamespacedNameKey: "default/http-server-6cbcc86f5d-lhq82",
		policyKey:            "default/deny-http-server-protect",
		srcAddrKey:           "10.244.0.5:49084",
	}
	obs := policyEventToObservation(otlpRecord(attrs, unixNano), attrs)

	require.Equal(t, unixNano, obs.Timestamp.UnixNano())
	require.Equal(t, "10.244.0.5:49084", obs.Source.OwnerName)
	require.Equal(t, "default", obs.Dest.Namespace)
	require.Equal(t, "http-server-6cbcc86f5d-lhq82", obs.Dest.OwnerName)
	require.Equal(t, corev1.ProtocolTCP, obs.Protocol)
	require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeProtect, obs.Action)
	require.Equal(t, "default", obs.DenyingPolicyNamespace)
	require.Equal(t, "deny-http-server-protect", obs.DenyingPolicyName)
}

func TestSplitNamespacedName(t *testing.T) {
	t.Parallel()

	namespace, name := splitNamespacedName("default/deny-http-server-protect")
	require.Equal(t, "default", namespace)
	require.Equal(t, "deny-http-server-protect", name)

	namespace, name = splitNamespacedName("no-separator")
	require.Empty(t, namespace)
	require.Equal(t, "no-separator", name)

	namespace, name = splitNamespacedName("")
	require.Empty(t, namespace)
	require.Empty(t, name)
}
