package controller

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// TestAttributionMetricsExposedOnMetricsEndpoint registers the counters the
// way main does and scrapes controller-runtime's metrics.Registry, which is
// what the manager serves on its metrics endpoint.
func TestAttributionMetricsExposedOnMetricsEndpoint(t *testing.T) {
	t.Parallel()

	sync, err := NewWorkloadNetworkPolicyStatusSync(nil, &WorkloadNetworkPolicyStatusSyncConfig{
		UpdateInterval:    time.Hour,
		MetricsRegisterer: metrics.Registry,
	})
	require.NoError(t, err)

	// A CounterVec is only exported once a child exists; creating one at zero
	// leaves the counter values untouched.
	sync.metrics.unattributed.WithLabelValues("kubernetes", "Egress", unattributedReasonNoTargetPolicy)
	sync.metrics.disagreements.WithLabelValues("kubernetes", "Egress")

	srv := httptest.NewServer(promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "# TYPE "+metricViolationsUnattributedTotal+" counter")
	require.Contains(t, string(body), "# TYPE "+metricAttributionDisagreementsTotal+" counter")
}

// TestRegisterAttributionMetricsIsIdempotent verifies a second registration
// on the same registry reuses the already registered counters.
func TestRegisterAttributionMetricsIsIdempotent(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	first, err := registerAttributionMetrics(reg)
	require.NoError(t, err)
	second, err := registerAttributionMetrics(reg)
	require.NoError(t, err)

	obs := newAttributionObservation(networkingv1.PolicyTypeEgress, deploymentRef("frontend"), offClusterPeer(), "")
	second.recordUnattributed(obs, unattributedReasonNoTargetPolicy)
	second.recordDisagreement(obs)

	require.InDelta(t, 1, testutil.ToFloat64(first.unattributed.WithLabelValues(
		string(obs.Provider), string(obs.Direction), unattributedReasonNoTargetPolicy)), 0)
	require.InDelta(t, 1, testutil.ToFloat64(first.disagreements.WithLabelValues(
		string(obs.Provider), string(obs.Direction))), 0)
}
