package scraper

import (
	"context"
	"log/slog"
	"testing"
	"time"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/istio"
	"github.com/rancher-sandbox/network-enforcer/internal/ringbuf"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/rancher-sandbox/network-enforcer/internal/violation"
	"github.com/stretchr/testify/require"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/embedded"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type fakeOtelEventLogger struct {
	embedded.Logger

	emitted []otellog.Record
}

func (f *fakeOtelEventLogger) Enabled(context.Context, otellog.EnabledParameters) bool { return true }

func (f *fakeOtelEventLogger) Emit(_ context.Context, rec otellog.Record) {
	f.emitted = append(f.emitted, rec.Clone())
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

	unixNano := time.Date(2026, 8, 3, 15, 39, 7, 0, time.UTC).UnixNano()
	wantTimestamp := time.Unix(0, unixNano)

	cases := []struct {
		name string
		// attrs is the single OTLP record exported in this case.
		attrs map[string]string
		// wantLearned is the learning event expected in the learning pipeline,
		// or nil when the record must not be routed there.
		wantLearned *types.LearningEvent
		// wantRecord is the violation buffer record expected, or nil when the
		// record must not reach the buffer.
		wantRecord *violation.Observation
		// wantOtel is the number of policy_violation_observed OTel logs emitted.
		wantOtel int
	}{
		{
			name: "learn routed to learning pipeline",
			attrs: map[string]string{
				eventTypeKey:    eventTypeLearn,
				dstNameKey:      "http-server-7bbf596dd9-4rgdc",
				dstNamespaceKey: "default",
				dstPortKey:      "18080",
				srcIdentityKey:  "spiffe://cluster.local/ns/default/sa/http-client-sa",
			},
			wantLearned: &types.LearningEvent{
				Dest: &securityv1alpha1.WorkloadRef{
					Namespace: "default",
					OwnerKind: securityv1alpha1.WorkloadKindDeployment,
					OwnerName: "http-server",
					Selector: metav1.LabelSelector{MatchLabels: map[string]string{
						"app": "http-server",
					}},
				},
				Source: &securityv1alpha1.WorkloadRef{
					Identity: "cluster.local/ns/default/sa/http-client-sa",
				},
				DstPort:  18080,
				Backend:  securityv1alpha1.PolicyBackendIstio,
				Protocol: corev1.ProtocolTCP,
			},
		},
		{
			name: "monitor dry-run DENY routed to violation buffer",
			attrs: map[string]string{
				eventTypeKey:         eventTypeMonitor,
				dstNamespacedNameKey: "default/http-server-7bbf596dd9-8gs65",
				policyKey:            "default/deny-http-server-monitor",
				srcAddrKey:           "10.244.0.9:46266",
			},
			wantRecord: &violation.Observation{
				Provider: securityv1alpha1.PolicyBackendIstio,
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Timestamp: metav1.NewTime(wantTimestamp),
					Source:    securityv1alpha1.WorkloadRef{OwnerName: "10.244.0.9:46266"},
					Dest: securityv1alpha1.WorkloadRef{
						Namespace: "default",
						OwnerName: "http-server-7bbf596dd9-8gs65",
					},
					Protocol:               corev1.ProtocolTCP,
					Action:                 securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
					DenyingPolicyNamespace: "default",
					DenyingPolicyName:      "deny-http-server-monitor",
				},
			},
			wantOtel: 1,
		},
		{
			name: "violation explicit DENY routed to violation buffer",
			attrs: map[string]string{
				eventTypeKey:         eventTypeProtect,
				dstNamespacedNameKey: "default/http-server-6cbcc86f5d-lhq82",
				policyKey:            "default/deny-http-server-protect",
				srcAddrKey:           "10.244.0.5:49084",
			},
			wantRecord: &violation.Observation{
				Provider: securityv1alpha1.PolicyBackendIstio,
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Timestamp: metav1.NewTime(wantTimestamp),
					Source:    securityv1alpha1.WorkloadRef{OwnerName: "10.244.0.5:49084"},
					Dest: securityv1alpha1.WorkloadRef{
						Namespace: "default",
						OwnerName: "http-server-6cbcc86f5d-lhq82",
					},
					Protocol:               corev1.ProtocolTCP,
					Action:                 securityv1alpha1.WorkloadNetworkPolicyModeProtect,
					DenyingPolicyNamespace: "default",
					DenyingPolicyName:      "deny-http-server-protect",
				},
			},
			wantOtel: 1,
		},
		{
			name: "violation ALLOW-miss routed to violation buffer without policy",
			attrs: map[string]string{
				eventTypeKey:         eventTypeProtect,
				dstNamespacedNameKey: "default/http-server-6cbcc86f5d-lhq82",
				srcAddrKey:           "10.244.0.5:52814",
			},
			wantRecord: &violation.Observation{
				Provider: securityv1alpha1.PolicyBackendIstio,
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Timestamp: metav1.NewTime(wantTimestamp),
					Source:    securityv1alpha1.WorkloadRef{OwnerName: "10.244.0.5:52814"},
					Dest: securityv1alpha1.WorkloadRef{
						Namespace: "default",
						OwnerName: "http-server-6cbcc86f5d-lhq82",
					},
					Protocol: corev1.ProtocolTCP,
					Action:   securityv1alpha1.WorkloadNetworkPolicyModeProtect,
				},
			},
			wantOtel: 1,
		},
		{
			name: "unknown event type is skipped",
			attrs: map[string]string{
				eventTypeKey: "something-else",
				dstNameKey:   "http-server",
			},
		},
		{
			name: "learn with out-of-range port is skipped",
			attrs: map[string]string{
				eventTypeKey:    eventTypeLearn,
				dstNameKey:      "http-server-7bbf596dd9-4rgdc",
				dstNamespaceKey: "default",
				dstPortKey:      "70000",
				srcIdentityKey:  "spiffe://cluster.local/ns/default/sa/http-client-sa",
			},
		},
		{
			name: "learn with non-numeric port is skipped",
			attrs: map[string]string{
				eventTypeKey:    eventTypeLearn,
				dstNameKey:      "http-server-7bbf596dd9-4rgdc",
				dstNamespaceKey: "default",
				dstPortKey:      "http",
				srcIdentityKey:  "spiffe://cluster.local/ns/default/sa/http-client-sa",
			},
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, securityv1alpha1.AddToScheme(scheme))
	learnDstPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "http-server-7bbf596dd9-4rgdc",
			Namespace: "default",
			Labels: map[string]string{
				appsv1.DefaultDeploymentUniqueLabelKey: "7bbf596dd9",
				"app":                                  "http-server",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: appsv1.SchemeGroupVersion.String(),
				Kind:       string(securityv1alpha1.WorkloadKindReplicaSet),
				Name:       "http-server-7bbf596dd9",
				UID:        "http-server-rs-uid",
				Controller: new(true),
			}},
		},
	}
	learnDstDeploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "http-server", Namespace: "default"},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "http-server"}},
		},
	}
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&corev1.Pod{}, istio.PodIPIndexField, istio.IndexPodByIP).
		WithObjects(learnDstPod, learnDstDeploy).
		Build()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			learned := make([]types.LearningEvent, 0)
			buffer := ringbuf.New[violation.Observation]()
			otelLogger := &fakeOtelEventLogger{}

			scraper := NewIstioScraper(IstioScraperConfig{
				EnqueueLearningEvent: func(ev types.LearningEvent) bool {
					learned = append(learned, ev)
					return true
				},
				ViolationBuffer:     buffer,
				ViolationOtelLogger: otelLogger,
				Logger:              slog.New(slog.DiscardHandler),
				Enricher:            istio.NewEnricher(cl),
			})

			_, err := scraper.Export(context.Background(), otlpRequest(otlpRecord(tc.attrs, unixNano)))
			require.NoError(t, err)

			if tc.wantLearned != nil {
				require.Equal(t, []types.LearningEvent{*tc.wantLearned}, learned)
			} else {
				require.Empty(t, learned)
			}

			drained := buffer.Drain()
			if tc.wantRecord != nil {
				require.Equal(t, []violation.Observation{*tc.wantRecord}, drained)
			} else {
				require.Empty(t, drained)
			}

			require.Len(t, otelLogger.emitted, tc.wantOtel)
		})
	}
}

// TestExportEnrichesObservations verifies that when the scraper is configured
// with an Enricher, the observation reaching both the OTel stream and the
// violation buffer carries the resolved source/destination workloads and SPIFFE
// identities, and that the owning WNP is resolved by selector for both protect
// and monitor events (WNP violations are always ALLOW-miss).
func TestExportEnrichesObservations(t *testing.T) {
	t.Parallel()

	unixNano := time.Date(2026, 8, 3, 15, 39, 7, 0, time.UTC).UnixNano()
	wantTimestamp := time.Unix(0, unixNano)

	const podTemplateHash = "6cbcc86f5d"
	const dstPodName = "http-server-" + podTemplateHash + "-lhq82"

	srcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "http-client-pod",
			Namespace: "default",
			UID:       "http-client-pod-uid",
		},
		Spec:   corev1.PodSpec{ServiceAccountName: "http-client-sa"},
		Status: corev1.PodStatus{PodIP: "10.244.0.9"},
	}
	dstPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      dstPodName,
			Namespace: "default",
			UID:       "http-server-pod-uid",
			Labels: map[string]string{
				appsv1.DefaultDeploymentUniqueLabelKey: podTemplateHash,
				"app":                                  "http-server",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: appsv1.SchemeGroupVersion.String(),
				Kind:       string(securityv1alpha1.WorkloadKindReplicaSet),
				Name:       "http-server-" + podTemplateHash,
				UID:        "http-server-rs-uid",
				Controller: new(true),
			}},
		},
		Spec: corev1.PodSpec{ServiceAccountName: "http-server-sa"},
	}
	// owningWNP selects the destination workload by label, so an ALLOW-miss (which
	// carries no denying policy on the wire) resolves its owning WNP by selector.
	owningWNP := &securityv1alpha1.WorkloadNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-http-server", Namespace: "default"},
		Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
			PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
				Backend: securityv1alpha1.PolicyBackendIstio,
				Istio: &securityv1alpha1.IstioAuthorizationPolicySpec{
					Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "http-server"}},
				},
			},
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, securityv1alpha1.AddToScheme(scheme))
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&corev1.Pod{}, istio.PodIPIndexField, istio.IndexPodByIP).
		WithObjects(srcPod, dstPod, owningWNP).
		Build()

	// The source and destination workloads resolve identically in both cases; only
	// the action and the owning/denying policy differ.
	wantSource := securityv1alpha1.WorkloadRef{
		Namespace: "default",
		OwnerKind: "Pod",
		OwnerName: "http-client-pod",
		Identity:  "cluster.local/ns/default/sa/http-client-sa",
	}
	wantDest := securityv1alpha1.WorkloadRef{
		Namespace: "default",
		OwnerKind: "Deployment",
		OwnerName: "http-server",
		Identity:  "cluster.local/ns/default/sa/http-server-sa",
	}

	cases := []struct {
		name  string
		attrs map[string]string
		want  violation.Observation
	}{
		{
			name: "protect ALLOW-miss resolves workloads and owning WNP by selector",
			attrs: map[string]string{
				eventTypeKey:         eventTypeProtect,
				dstNamespacedNameKey: "default/" + dstPodName,
				srcAddrKey:           "10.244.0.9:46266",
			},
			want: violation.Observation{
				Provider: securityv1alpha1.PolicyBackendIstio,
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Timestamp:              metav1.NewTime(wantTimestamp),
					Source:                 wantSource,
					Dest:                   wantDest,
					Protocol:               corev1.ProtocolTCP,
					Action:                 securityv1alpha1.WorkloadNetworkPolicyModeProtect,
					DenyingPolicyNamespace: "default",
					DenyingPolicyName:      "allow-http-server",
				},
			},
		},
		{
			name: "monitor ALLOW-miss resolves workloads and owning WNP by selector",
			attrs: map[string]string{
				eventTypeKey:         eventTypeMonitor,
				dstNamespacedNameKey: "default/" + dstPodName,
				srcAddrKey:           "10.244.0.9:46266",
			},
			want: violation.Observation{
				Provider: securityv1alpha1.PolicyBackendIstio,
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Timestamp:              metav1.NewTime(wantTimestamp),
					Source:                 wantSource,
					Dest:                   wantDest,
					Protocol:               corev1.ProtocolTCP,
					Action:                 securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
					DenyingPolicyNamespace: "default",
					DenyingPolicyName:      "allow-http-server",
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			buffer := ringbuf.New[violation.Observation]()
			otelLogger := &fakeOtelEventLogger{}
			scraper := NewIstioScraper(IstioScraperConfig{
				ViolationBuffer:     buffer,
				ViolationOtelLogger: otelLogger,
				Logger:              slog.New(slog.DiscardHandler),
				Enricher:            istio.NewEnricher(cl),
			})

			_, err := scraper.Export(context.Background(), otlpRequest(otlpRecord(tc.attrs, unixNano)))
			require.NoError(t, err)

			require.Equal(t, []violation.Observation{tc.want}, buffer.Drain())
			require.Len(t, otelLogger.emitted, 1)
		})
	}
}

func TestPolicyEventToObservation(t *testing.T) {
	t.Parallel()

	unixNano := time.Date(2026, 8, 3, 15, 39, 7, 0, time.UTC).UnixNano()

	attrs := map[string]string{
		eventTypeKey:         eventTypeProtect,
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
