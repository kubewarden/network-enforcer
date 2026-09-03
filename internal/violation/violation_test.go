package violation

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/embedded"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

type fakeOtelLogger struct {
	embedded.Logger

	emitted []otellog.Record
}

func (f *fakeOtelLogger) Enabled(context.Context, otellog.EnabledParameters) bool { return true }

func (f *fakeOtelLogger) Emit(_ context.Context, rec otellog.Record) {
	f.emitted = append(f.emitted, rec.Clone())
}

func testObservation() Observation {
	return Observation{
		Provider:  securityv1alpha1.PolicyBackendIstio,
		Timestamp: metav1.NewTime(time.Date(2026, 8, 3, 15, 39, 7, 0, time.UTC)),
		Source: securityv1alpha1.WorkloadRef{
			Namespace: "default",
			OwnerName: "http-client-1",
			Identity:  "spiffe://cluster.local/ns/default/sa/http-client-sa",
		},
		Dest: securityv1alpha1.WorkloadRef{
			Namespace: "default",
			OwnerName: "http-server-1",
			Identity:  "cluster.local/ns/default/sa/http-server-sa",
		},
		Protocol: corev1.ProtocolTCP,
		DstPort:  80,
		Action:   securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
	}
}

func TestObservationCarriesViolationInfo(t *testing.T) {
	obs := testObservation()

	require.Equal(t, "http-server-1", obs.Dest.OwnerName)
	require.Equal(t, int32(80), obs.DstPort)
	require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeMonitor, obs.Action)
	require.Equal(t, securityv1alpha1.PolicyBackendIstio, obs.Provider)
	require.Equal(t, "spiffe://cluster.local/ns/default/sa/http-client-sa", obs.Source.Identity)
}

func TestEmitOtelLogSchema(t *testing.T) {
	logger := &fakeOtelLogger{}

	obs := testObservation()
	obs.DenyingPolicyNamespace = "default"
	obs.DenyingPolicyName = "deny-http-server"

	EmitOtelLog(context.Background(), logger, obs)
	require.Len(t, logger.emitted, 1)

	attrs := map[string]string{}
	logger.emitted[0].WalkAttributes(func(kv attribute.KeyValue) bool {
		attrs[string(kv.Key)] = kv.Value.String()
		return true
	})

	require.Equal(t, "istio", attrs["enforcement.provider"])
	require.Equal(t, "monitor", attrs["action"])
	require.Equal(t, "http-client-1", attrs["source.workload.name"])
	require.Equal(t, "default", attrs["source.workload.namespace"])
	require.Equal(t, "spiffe://cluster.local/ns/default/sa/http-client-sa", attrs["source.workload.identity"])
	require.Equal(t, "http-server-1", attrs["destination.workload.name"])
	require.Equal(t, "default", attrs["destination.workload.namespace"])
	require.Equal(t, "cluster.local/ns/default/sa/http-server-sa", attrs["destination.workload.identity"])
	require.Equal(t, "TCP", attrs["network.transport"])
	require.Equal(t, "80", attrs["destination.port"])
	require.Equal(t, "default", attrs["policy.ref.namespace"])
	require.Equal(t, "deny-http-server", attrs["policy.ref.name"])

	// Empty kind must not be exported (no empty placeholders).
	_, ok := attrs["source.workload.kind"]
	require.False(t, ok, "kind is unknown for istio and must be omitted")
	_, ok = attrs["destination.workload.kind"]
	require.False(t, ok, "kind is unknown for istio and must be omitted")

	// No-op when the logger is nil.
	require.NotPanics(t, func() { EmitOtelLog(context.Background(), nil, obs) })
}

func TestEmitOtelLogAllowMiss(t *testing.T) {
	logger := &fakeOtelLogger{}

	obs := testObservation()

	EmitOtelLog(context.Background(), logger, obs)
	require.Len(t, logger.emitted, 1)

	attrs := map[string]string{}
	logger.emitted[0].WalkAttributes(func(kv attribute.KeyValue) bool {
		attrs[string(kv.Key)] = kv.Value.String()
		return true
	})

	_, ok := attrs["policy.ref.name"]
	require.False(t, ok, "allow-miss must not fabricate a denying policy")
	_, ok = attrs["policy.ref.namespace"]
	require.False(t, ok, "allow-miss must not fabricate a denying policy")
}
