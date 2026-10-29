package scraper

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/embedded"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/istio"
	"github.com/kubewarden/network-enforcer/internal/ringbuf"
	"github.com/kubewarden/network-enforcer/internal/tlsutil"
	"github.com/kubewarden/network-enforcer/internal/types"
	"github.com/kubewarden/network-enforcer/internal/violation"
	"github.com/kubewarden/network-enforcer/internal/workload"
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

func deploymentTarget(name string) securityv1alpha1.WorkloadTargetRef {
	return securityv1alpha1.WorkloadTargetRef{Kind: securityv1alpha1.WorkloadKindDeployment, Name: name}
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
				eventTypeKey:    string(types.EventTypeLearn),
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
				eventTypeKey:         string(types.EventTypeMonitor),
				dstNamespacedNameKey: "default/http-server-7bbf596dd9-8gs65",
				policyKey:            "default/deny-http-server-monitor",
				srcAddrKey:           "10.244.0.9:46266",
			},
			wantRecord: &violation.Observation{
				Provider:  securityv1alpha1.PolicyBackendIstio,
				Direction: networkingv1.PolicyTypeIngress,
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
			wantOtel: 1,
		},
		{
			name: "violation explicit DENY routed to violation buffer",
			attrs: map[string]string{
				eventTypeKey:         string(types.EventTypeProtect),
				dstNamespacedNameKey: "default/http-server-6cbcc86f5d-lhq82",
				policyKey:            "default/deny-http-server-protect",
				srcAddrKey:           "10.244.0.5:49084",
			},
			wantRecord: &violation.Observation{
				Provider:  securityv1alpha1.PolicyBackendIstio,
				Direction: networkingv1.PolicyTypeIngress,
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
			wantOtel: 1,
		},
		{
			name: "violation ALLOW-miss routed to violation buffer without policy",
			attrs: map[string]string{
				eventTypeKey:         string(types.EventTypeProtect),
				dstNamespacedNameKey: "default/http-server-6cbcc86f5d-lhq82",
				srcAddrKey:           "10.244.0.5:52814",
			},
			wantRecord: &violation.Observation{
				Provider:  securityv1alpha1.PolicyBackendIstio,
				Direction: networkingv1.PolicyTypeIngress,
				Timestamp: metav1.NewTime(wantTimestamp),
				Source:    securityv1alpha1.WorkloadRef{OwnerName: "10.244.0.5:52814"},
				Dest: securityv1alpha1.WorkloadRef{
					Namespace: "default",
					OwnerName: "http-server-6cbcc86f5d-lhq82",
				},
				Protocol: corev1.ProtocolTCP,
				Action:   securityv1alpha1.WorkloadNetworkPolicyModeProtect,
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
				eventTypeKey:    string(types.EventTypeLearn),
				dstNameKey:      "http-server-7bbf596dd9-4rgdc",
				dstNamespaceKey: "default",
				dstPortKey:      "70000",
				srcIdentityKey:  "spiffe://cluster.local/ns/default/sa/http-client-sa",
			},
		},
		{
			name: "learn with non-numeric port is skipped",
			attrs: map[string]string{
				eventTypeKey:    string(types.EventTypeLearn),
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
	}
	learnDstDeploy := &appsv1.Deployment{
		Name: "http-server", Namespace: "default",
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "http-server"}},
		},
	}
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&corev1.Pod{}, istio.PodIPIndexField, istio.IndexPodByIP).
		WithIndex(&securityv1alpha1.WorkloadNetworkPolicy{}, workload.WNPTargetIndexField, workload.IndexWNPByTarget).
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
// identities, and that the owning WNP is resolved by targetRef for both protect
// and monitor events (WNP violations are always ALLOW-miss).
func TestExportEnrichesObservations(t *testing.T) {
	t.Parallel()

	unixNano := time.Date(2026, 8, 3, 15, 39, 7, 0, time.UTC).UnixNano()
	wantTimestamp := time.Unix(0, unixNano)

	const podTemplateHash = "6cbcc86f5d"
	const dstPodName = "http-server-" + podTemplateHash + "-lhq82"

	srcPod := &corev1.Pod{
		Name:      "http-client-pod",
		Namespace: "default",
		UID:       "http-client-pod-uid",
		Spec:      corev1.PodSpec{ServiceAccountName: "http-client-sa"},
		Status:    corev1.PodStatus{PodIP: "10.244.0.9"},
	}
	dstPod := &corev1.Pod{
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
		Spec: corev1.PodSpec{ServiceAccountName: "http-server-sa"},
	}
	// owningWNP selects the destination workload by label, so an ALLOW-miss (which
	// carries no denying policy on the wire) resolves its owning WNP by targetRef.
	owningWNP := &securityv1alpha1.WorkloadNetworkPolicy{
		Name: "allow-http-server", Namespace: "default",
		Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
			PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
				Backend: securityv1alpha1.PolicyBackendIstio,
				Istio: &securityv1alpha1.IstioAuthorizationPolicySpec{
					Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "http-server"}},
				},
			},
			WorkloadTargetingSpec: securityv1alpha1.WorkloadTargetingSpec{
				TargetRef: deploymentTarget("http-server"),
				Direction: networkingv1.PolicyTypeIngress,
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
		WithIndex(&securityv1alpha1.WorkloadNetworkPolicy{}, workload.WNPTargetIndexField, workload.IndexWNPByTarget).
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
			name: "protect ALLOW-miss resolves workloads and owning WNP by targetRef",
			attrs: map[string]string{
				eventTypeKey:         string(types.EventTypeProtect),
				dstNamespacedNameKey: "default/" + dstPodName,
				srcAddrKey:           "10.244.0.9:46266",
			},
			want: violation.Observation{
				Provider:  securityv1alpha1.PolicyBackendIstio,
				Direction: networkingv1.PolicyTypeIngress,
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
			name: "monitor ALLOW-miss resolves workloads and owning WNP by targetRef",
			attrs: map[string]string{
				eventTypeKey:         string(types.EventTypeMonitor),
				dstNamespacedNameKey: "default/" + dstPodName,
				srcAddrKey:           "10.244.0.9:46266",
			},
			want: violation.Observation{
				Provider:  securityv1alpha1.PolicyBackendIstio,
				Direction: networkingv1.PolicyTypeIngress,
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
		eventTypeKey:         string(types.EventTypeProtect),
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
	require.Equal(t, networkingv1.PolicyTypeIngress, obs.Direction)
	require.Equal(t, "default", obs.DenyingPolicyNamespace)
	require.Equal(t, "deny-http-server-protect", obs.DenyingPolicyName)
}

func writeIstioTLSCertDir(t *testing.T) string {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"Test Leaf"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	keyBytes, err := x509.MarshalECPrivateKey(leafKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, tlsutil.CAFile), caPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, tlsutil.CertFile), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, tlsutil.KeyFile), keyPEM, 0o600))
	return dir
}

func freeLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

func TestStartTLSInvalidCertDir(t *testing.T) {
	t.Parallel()

	scraper := NewIstioScraper(IstioScraperConfig{
		Logger:     slog.New(slog.DiscardHandler),
		OtelPort:   freeLocalPort(t),
		TLSCertDir: t.TempDir(), // empty dir: missing tls.crt / tls.key / ca.crt
	})

	err := scraper.Start(context.Background())
	require.ErrorContains(t, err, "failed to load TLS credentials for OTLP logs server")
}

func TestStartTLSClient(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		creds   func(t *testing.T, certDir string) credentials.TransportCredentials
		wantErr bool
	}{
		{
			name: "rejects plaintext client",
			creds: func(t *testing.T, _ string) credentials.TransportCredentials {
				t.Helper()
				return insecure.NewCredentials()
			},
			wantErr: true,
		},
		{
			name: "rejects TLS client without a client certificate",
			creds: func(t *testing.T, certDir string) credentials.TransportCredentials {
				t.Helper()
				caPool, err := tlsutil.LoadCACertPool(filepath.Join(certDir, tlsutil.CAFile))
				require.NoError(t, err)
				return credentials.NewTLS(&tls.Config{
					MinVersion: tls.VersionTLS13,
					RootCAs:    caPool,
					ServerName: "localhost",
				})
			},
			wantErr: true,
		},
		{
			name: "accepts mTLS client",
			creds: func(t *testing.T, certDir string) credentials.TransportCredentials {
				t.Helper()
				creds, err := tlsutil.ClientCredentials(certDir, "localhost")
				require.NoError(t, err)
				return creds
			},
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			certDir := writeIstioTLSCertDir(t)
			port := freeLocalPort(t)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			scraper := NewIstioScraper(IstioScraperConfig{
				Logger:     slog.New(slog.DiscardHandler),
				OtelPort:   port,
				TLSCertDir: certDir,
			})

			errCh := make(chan error, 1)
			go func() {
				errCh <- scraper.Start(ctx)
			}()

			addr := fmt.Sprintf("127.0.0.1:%d", port)
			require.Eventually(t, func() bool {
				conn, err := net.Dial("tcp", addr)
				if err != nil {
					return false
				}
				_ = conn.Close()
				return true
			}, 2*time.Second, 20*time.Millisecond)

			conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(tc.creds(t, certDir)))
			require.NoError(t, err)

			rpcCtx, rpcCancel := context.WithTimeout(ctx, 3*time.Second)
			defer rpcCancel()
			_, err = collogspb.NewLogsServiceClient(conn).Export(rpcCtx, &collogspb.ExportLogsServiceRequest{})
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			require.NoError(t, conn.Close())
			cancel()
			require.NoError(t, <-errCh)
		})
	}
}

// TestExportReportedPolicyOfOtherWorkloadCountsDisagreement is a scraper-to-sync
// regression: when ztunnel reports a policy owned by a WNP targeting another
// workload (overlapping selectors), enrichment must keep it so the controller
// counts the disagreement, while the violation is still attributed to the
// subject's own WNP.
func TestExportReportedPolicyOfOtherWorkloadCountsDisagreement(t *testing.T) {
	t.Parallel()

	const podTemplateHash = "6cbcc86f5d"
	const dstPodName = "http-server-" + podTemplateHash + "-lhq82"

	dstPod := &corev1.Pod{
		Name:      dstPodName,
		Namespace: "default",
		Labels: map[string]string{
			appsv1.DefaultDeploymentUniqueLabelKey: podTemplateHash,
			"app":                                  "http-server",
		},
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: appsv1.SchemeGroupVersion.String(),
			Kind:       string(securityv1alpha1.WorkloadKindReplicaSet),
			Name:       "http-server-" + podTemplateHash,
			Controller: new(true),
		}},
		Spec: corev1.PodSpec{ServiceAccountName: "http-server-sa"},
	}
	ingressWNP := func(name, target string) *securityv1alpha1.WorkloadNetworkPolicy {
		return &securityv1alpha1.WorkloadNetworkPolicy{
			Name: name, Namespace: "default",
			Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
				PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
					Backend: securityv1alpha1.PolicyBackendIstio,
					Istio: &securityv1alpha1.IstioAuthorizationPolicySpec{
						Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "http-server"}},
					},
				},
				WorkloadTargetingSpec: securityv1alpha1.WorkloadTargetingSpec{
					TargetRef: deploymentTarget(target),
					Direction: networkingv1.PolicyTypeIngress,
				},
			},
		}
	}

	// ownedAP is the AuthorizationPolicy the controller renders for wnp.
	ownedAP := func(wnp *securityv1alpha1.WorkloadNetworkPolicy) *istiosecurityv1.AuthorizationPolicy {
		return &istiosecurityv1.AuthorizationPolicy{
			Name:      wnp.Name,
			Namespace: wnp.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
				wnp, securityv1alpha1.GroupVersion.WithKind(securityv1alpha1.WorkloadNetworkPolicyKind))},
		}
	}
	serverWNP := ingressWNP("allow-http-server", "http-server")
	canaryWNP := ingressWNP("allow-http-canary", "http-canary")

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, networkingv1.AddToScheme(scheme))
	require.NoError(t, securityv1alpha1.AddToScheme(scheme))
	require.NoError(t, istiosecurityv1.AddToScheme(scheme))
	// http-canary's WNP selects the http-server pods too, so ztunnel reports its
	// AuthorizationPolicy for traffic whose subject is Deployment/http-server.
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&corev1.Pod{}, istio.PodIPIndexField, istio.IndexPodByIP).
		WithIndex(&securityv1alpha1.WorkloadNetworkPolicy{}, workload.WNPTargetIndexField, workload.IndexWNPByTarget).
		WithStatusSubresource(&securityv1alpha1.WorkloadNetworkPolicy{}).
		WithObjects(dstPod, serverWNP, canaryWNP, ownedAP(serverWNP), ownedAP(canaryWNP)).
		Build()

	buffer := ringbuf.New[violation.Observation]()
	scraper := NewIstioScraper(IstioScraperConfig{
		ViolationBuffer: buffer,
		Logger:          slog.New(slog.DiscardHandler),
		Enricher:        istio.NewEnricher(cl),
	})
	attrs := map[string]string{
		eventTypeKey:         string(types.EventTypeProtect),
		dstNamespacedNameKey: "default/" + dstPodName,
		policyKey:            "default/allow-http-canary",
		srcAddrKey:           "10.244.0.9:46266",
	}
	_, err := scraper.Export(context.Background(), otlpRequest(otlpRecord(attrs, time.Now().UnixNano())))
	require.NoError(t, err)

	reg := startStatusSync(t, cl, buffer)

	subjectWNP := k8stypes.NamespacedName{Namespace: "default", Name: "allow-http-server"}
	require.Eventually(t, func() bool {
		var wnp securityv1alpha1.WorkloadNetworkPolicy
		if cl.Get(context.Background(), subjectWNP, &wnp) != nil || len(wnp.Status.Violations) != 1 {
			return false
		}
		return wnp.Status.Violations[0].DenyingPolicyName == subjectWNP.Name &&
			gatheredCounter(reg, disagreementMetric, map[string]string{"provider": "istio"}) == 1
	}, 5*time.Second, 20*time.Millisecond)

	var canary securityv1alpha1.WorkloadNetworkPolicy
	require.NoError(t, cl.Get(context.Background(), canaryWNP.NamespacedName(), &canary))
	require.Empty(t, canary.Status.Violations, "the reported policy's WNP must not get the violation")
	require.Zero(t, gatheredCounter(reg, unattributedMetric, map[string]string{"provider": "istio"}))
}
