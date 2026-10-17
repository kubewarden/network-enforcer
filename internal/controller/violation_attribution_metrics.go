package controller

import (
	"errors"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/kubewarden/network-enforcer/internal/violation"
)

const (
	metricViolationsUnattributedTotal       = "network_enforcer_violations_unattributed_total"
	metricAttributionDisagreementsTotal     = "network_enforcer_violation_attribution_disagreements_total"
	metricLabelProvider                     = "provider"
	metricLabelDirection                    = "direction"
	metricLabelReason                       = "reason"
	unattributedReasonUnknownSubject        = "unknown_subject"
	unattributedReasonNoTargetPolicy        = "no_target_policy"
	unattributedReasonDuplicateTargetPolicy = "duplicate_target_policy"
	unattributedReasonLookupFailed          = "lookup_failed"
)

// attributionMetrics holds the counters of the violation attribution chain.
type attributionMetrics struct {
	unattributed  *prometheus.CounterVec
	disagreements *prometheus.CounterVec
}

func newAttributionMetrics() *attributionMetrics {
	return &attributionMetrics{
		unattributed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricViolationsUnattributedTotal,
			Help: "Number of policy violations that could not be attributed to a WorkloadNetworkPolicy.",
		}, []string{metricLabelProvider, metricLabelDirection, metricLabelReason}),
		disagreements: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricAttributionDisagreementsTotal,
			Help: "Number of policy violations whose data-plane reported policy is owned by a " +
				"WorkloadNetworkPolicy targeting a workload other than the violation subject.",
		}, []string{metricLabelProvider, metricLabelDirection}),
	}
}

// registerAttributionMetrics creates the attribution counters and registers
// them on reg.
func registerAttributionMetrics(reg prometheus.Registerer) (*attributionMetrics, error) {
	m := newAttributionMetrics()
	var err error
	if m.unattributed, err = registerCounterVec(reg, m.unattributed); err != nil {
		return nil, err
	}
	if m.disagreements, err = registerCounterVec(reg, m.disagreements); err != nil {
		return nil, err
	}
	return m, nil
}

func registerCounterVec(reg prometheus.Registerer, c *prometheus.CounterVec) (*prometheus.CounterVec, error) {
	err := reg.Register(c)
	if err == nil {
		return c, nil
	}
	if alreadyRegistered, ok := errors.AsType[prometheus.AlreadyRegisteredError](err); ok {
		if existing, isVec := alreadyRegistered.ExistingCollector.(*prometheus.CounterVec); isVec {
			return existing, nil
		}
	}
	return nil, fmt.Errorf("registering violation attribution metrics: %w", err)
}

func (m *attributionMetrics) recordUnattributed(obs violation.Observation, reason string) {
	if m == nil {
		return
	}
	m.unattributed.WithLabelValues(string(obs.Provider), string(obs.Direction), reason).Inc()
}

func (m *attributionMetrics) recordDisagreement(obs violation.Observation) {
	if m == nil {
		return
	}
	m.disagreements.WithLabelValues(string(obs.Provider), string(obs.Direction)).Inc()
}
