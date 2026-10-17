package scraper

import (
	"context"
	"math"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	hubbleObserver "github.com/cilium/cilium/api/v1/observer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/controller"
	"github.com/kubewarden/network-enforcer/internal/ringbuf"
	"github.com/kubewarden/network-enforcer/internal/testutil"
	"github.com/kubewarden/network-enforcer/internal/violation"
	"github.com/kubewarden/network-enforcer/internal/workload"
)

func TestPortToInt32(t *testing.T) {
	t.Parallel()

	t.Run("uint32", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			name    string
			port    uint32
			want    int32
			wantErr bool
		}{
			{name: "zero means unavailable", port: 0, want: 0},
			{name: "valid port", port: 8080, want: 8080},
			{name: "max valid port", port: maxValidPort, want: maxValidPort},
			{name: "above max valid port", port: maxValidPort + 1, wantErr: true},
			{name: "max int32", port: math.MaxInt32, wantErr: true},
			{name: "max uint32", port: math.MaxUint32, wantErr: true},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				got, err := portToInt32(tc.port)
				if tc.wantErr {
					require.ErrorIs(t, err, errPortOutOfRange)
					require.Zero(t, got)
					return
				}
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			})
		}
	})

	t.Run("int64", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			name    string
			port    int64
			want    int32
			wantErr bool
		}{
			{name: "zero means unavailable", port: 0, want: 0},
			{name: "valid port", port: 8080, want: 8080},
			{name: "max valid port", port: maxValidPort, want: maxValidPort},
			{name: "above max valid port", port: maxValidPort + 1, wantErr: true},
			{name: "max int32", port: math.MaxInt32, wantErr: true},
			{name: "above max int32", port: math.MaxInt32 + 1, wantErr: true},
			{name: "negative", port: -1, wantErr: true},
			{name: "min int64", port: math.MinInt64, wantErr: true},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				got, err := portToInt32(tc.port)
				if tc.wantErr {
					require.ErrorIs(t, err, errPortOutOfRange)
					require.Zero(t, got)
					return
				}
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			})
		}
	})
}

func TestParsePort(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		port           string
		want           int32
		wantOutOfRange bool
		wantErr        bool
	}{
		{name: "min valid port", port: "1", want: minValidPort},
		{name: "valid port", port: "18080", want: 18080},
		{name: "max valid port", port: "65535", want: maxValidPort},
		{name: "zero is out of range", port: "0", wantErr: true, wantOutOfRange: true},
		{name: "negative is out of range", port: "-1", wantErr: true, wantOutOfRange: true},
		{name: "above max valid port", port: "65536", wantErr: true, wantOutOfRange: true},
		{name: "above max int32", port: "2147483648", wantErr: true},
		{name: "non numeric", port: "http", wantErr: true},
		{name: "empty", port: "", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parsePort(tc.port)
			if tc.wantErr {
				require.Error(t, err)
				require.Zero(t, got)
				if tc.wantOutOfRange {
					require.ErrorIs(t, err, errPortOutOfRange)
				} else {
					require.NotErrorIs(t, err, errPortOutOfRange)
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestUnattributedFlowViolationReachesStatusSync is a scraper-to-sync
// regression: a dropped flow whose subject is targeted by no
// WorkloadNetworkPolicy, or by several, must still be recorded as a violation
// and reach the status sync, which counts it as unattributed.
func TestUnattributedFlowViolationReachesStatusSync(t *testing.T) {
	t.Parallel()

	const ns = defaultCiliumTestNamespace

	scheme := runtime.NewScheme()
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, networkingv1.AddToScheme(scheme))
	require.NoError(t, securityv1alpha1.AddToScheme(scheme))

	deployment := func(name string) *appsv1.Deployment {
		return &appsv1.Deployment{
			Name: name, Namespace: ns,
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			},
		}
	}
	egressWNP := func(name, target string) *securityv1alpha1.WorkloadNetworkPolicy {
		return &securityv1alpha1.WorkloadNetworkPolicy{
			Name: name, Namespace: ns,
			Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
				PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
					Backend: securityv1alpha1.PolicyBackendKubernetes,
					Kubernetes: &networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": target}},
						PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
					},
				},
				WorkloadTargetingSpec: securityv1alpha1.WorkloadTargetingSpec{
					TargetRef: deploymentTarget(target),
					Direction: networkingv1.PolicyTypeEgress,
				},
			},
		}
	}
	deniedEgressFlow := func(src, dst string) *hubbleObserver.GetFlowsResponse {
		return flowResponse(&flowpb.Flow{
			Verdict:          flowpb.Verdict_DROPPED,
			DropReasonDesc:   hubbleObserver.DropReason_POLICY_DENIED,
			TrafficDirection: hubbleObserver.TrafficDirection_EGRESS,
			L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
			Source: &hubbleObserver.Endpoint{
				Namespace: ns,
				Workloads: []*flowpb.Workload{{Name: src, Kind: "Deployment"}},
			},
			Destination: &hubbleObserver.Endpoint{
				Namespace: ns,
				Workloads: []*flowpb.Workload{{Name: dst, Kind: "Deployment"}},
			},
		})
	}

	// Deployment/orphan has no WNP; Deployment/dup has two egress WNPs.
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&securityv1alpha1.WorkloadNetworkPolicy{}, workload.WNPTargetIndexField, workload.IndexWNPByTarget).
		WithStatusSubresource(&securityv1alpha1.WorkloadNetworkPolicy{}).
		WithObjects(
			deployment("orphan"), deployment("dup"), deployment("peer"),
			egressWNP("dup-egress-a", "dup"), egressWNP("dup-egress-b", "dup"),
		).
		Build()

	s := NewCiliumScraper(CiliumScraperConfig{Client: cl, Logger: testutil.NewTestLogger(t)})
	buffer := ringbuf.New[violation.Observation]()

	for _, subject := range []string{"orphan", "dup"} {
		result := s.processFlow(t.Context(), deniedEgressFlow(subject, "peer"))
		require.Equal(t, processFlowOutcomeViolation, result.outcome, "subject %s", subject)
		require.Empty(t, result.observation.DenyingPolicyName, "subject %s", subject)
		// Mirrors the scraper loop, which emits the OTel log and buffers every
		// processFlowOutcomeViolation.
		buffer.Record(result.observation)
	}

	reg := startStatusSync(t, cl, buffer)

	require.Eventually(t, func() bool {
		return gatheredCounter(reg, unattributedMetric, map[string]string{"reason": "no_target_policy"}) == 1 &&
			gatheredCounter(reg, unattributedMetric, map[string]string{"reason": "duplicate_target_policy"}) == 1
	}, 5*time.Second, 20*time.Millisecond)
}

// startStatusSync runs the controller's WorkloadNetworkPolicyStatusSync on a
// short interval against buffer, until the test ends, and returns the registry
// its attribution metrics are registered on.
func startStatusSync(
	t *testing.T,
	cl client.Client,
	buffer *ringbuf.Buffer[violation.Observation],
) *prometheus.Registry {
	t.Helper()

	reg := prometheus.NewRegistry()
	sync, err := controller.NewWorkloadNetworkPolicyStatusSync(cl, &controller.WorkloadNetworkPolicyStatusSyncConfig{
		UpdateInterval:    10 * time.Millisecond,
		ViolationBuffer:   buffer,
		MetricsRegisterer: reg,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = sync.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return reg
}

const (
	unattributedMetric = "network_enforcer_violations_unattributed_total"
	disagreementMetric = "network_enforcer_violation_attribution_disagreements_total"
)

// gatheredCounter returns the value of the counter series of the metric name
// carrying all the given labels, 0 when there is none, or -1 when the registry
// cannot be read.
func gatheredCounter(reg *prometheus.Registry, name string, labels map[string]string) float64 {
	families, err := reg.Gather()
	if err != nil {
		return -1
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, m := range family.GetMetric() {
			matched := 0
			for _, label := range m.GetLabel() {
				if want, ok := labels[label.GetName()]; ok && want == label.GetValue() {
					matched++
				}
			}
			if matched == len(labels) {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}
