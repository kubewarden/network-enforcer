package v1alpha1

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func mkViolation() ViolationRecord {
	return ViolationRecord{
		ID:        0,
		Timestamp: metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		Source: WorkloadRef{
			Namespace: "ns1",
			OwnerKind: "Deployment",
			OwnerName: "app",
		},
		Dest: WorkloadRef{
			Namespace: "ns2",
			OwnerKind: "Service",
			OwnerName: "svc",
		},
		Protocol:               corev1.ProtocolTCP,
		DstPort:                80,
		Action:                 "protect",
		DenyingPolicyNamespace: "ns1",
		DenyingPolicyName:      "deny-all",
	}
}

// withID returns a copy with a different ID.
func (r ViolationRecord) withID(id int64) ViolationRecord {
	r.ID = id
	return r
}

// withTimestamp returns a copy with a different timestamp.
func (r ViolationRecord) withTimestamp(ts time.Time) ViolationRecord {
	r.Timestamp = metav1.NewTime(ts)
	return r
}

// withDstPort returns a copy with a different destination port.
func (r ViolationRecord) withDstPort(port int32) ViolationRecord {
	r.DstPort = port
	return r
}

// withDest returns a copy with a different destination name.
func (r ViolationRecord) withDest(ns, name string) ViolationRecord {
	r.Dest = WorkloadRef{Namespace: ns, OwnerKind: "Service", OwnerName: name}
	return r
}

// withSource returns a copy with a different source name.
func (r ViolationRecord) withSource(ns, name string) ViolationRecord {
	r.Source = WorkloadRef{Namespace: ns, OwnerKind: "Deployment", OwnerName: name}
	return r
}

// withSourceIdentity returns a copy with a different source identity.
func (r ViolationRecord) withSourceIdentity(identity string) ViolationRecord {
	r.Source.Identity = identity
	return r
}

// withProtocol returns a copy with a different protocol.
func (r ViolationRecord) withProtocol(proto corev1.Protocol) ViolationRecord {
	r.Protocol = proto
	return r
}

// withAction returns a copy with a different action.
func (r ViolationRecord) withAction(action WorkloadNetworkPolicyMode) ViolationRecord {
	r.Action = action
	return r
}

// withDenyingPolicy returns a copy with a different denying policy.
func (r ViolationRecord) withDenyingPolicy(ns, name string) ViolationRecord {
	r.DenyingPolicyNamespace = ns
	r.DenyingPolicyName = name
	return r
}

func TestViolationRecordKey(t *testing.T) {
	base := mkViolation()

	// Same violation (different timestamp) → same key.
	require.Equal(t, base.Key(), base.withTimestamp(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)).Key(),
		"timestamp must not change the key")

	// Different source → different keys.
	require.NotEqual(t, base.Key(), base.withSource("other-ns", "other-app").Key())

	// Different source identity → different keys (distinct principals are
	// distinct violations even in the same namespace).
	require.NotEqual(t, base.Key(), base.withSourceIdentity("spiffe://cluster.local/ns/ns1/sa/other-sa").Key())

	// Different dest → different keys.
	require.NotEqual(t, base.Key(), base.withDest("other-ns", "other-svc").Key())

	// Different protocol → different keys.
	require.NotEqual(t, base.Key(), base.withProtocol(corev1.ProtocolUDP).Key())

	// Different dstPort → different keys.
	require.NotEqual(t, base.Key(), base.withDstPort(443).Key())

	// Different action → different keys.
	require.NotEqual(t, base.Key(), base.withAction("monitor").Key())

	// Different denying policy → different keys.
	require.NotEqual(t, base.Key(), base.withDenyingPolicy("ns1", "other-policy").Key())
}

func TestMergeScrapedViolations(t *testing.T) {
	baseTS := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	baseViolation := mkViolation().withTimestamp(baseTS.Time)

	baseStatus := WorkloadNetworkPolicyStatus{
		Violations:     []ViolationRecord{baseViolation},
		ViolationCount: 1,
	}

	tests := []struct {
		name           string
		scraped        []ViolationRecord
		initialStatus  WorkloadNetworkPolicyStatus
		expectedStatus WorkloadNetworkPolicyStatus
	}{
		{
			name:           "no_scraped_violations",
			scraped:        nil,
			initialStatus:  baseStatus,
			expectedStatus: baseStatus,
		},
		{
			name: "scrape_new_violations",
			scraped: []ViolationRecord{
				baseViolation.withDest("ns2", "svc2").withDstPort(443).
					withTimestamp(baseTS.Time.Add(time.Minute)),
				baseViolation.withDest("ns2", "svc3").withDstPort(8080).
					withTimestamp(baseTS.Time.Add(2 * time.Minute)),
			},
			initialStatus: baseStatus,
			expectedStatus: WorkloadNetworkPolicyStatus{
				Violations: []ViolationRecord{
					baseViolation.withDest("ns2", "svc3").withDstPort(8080).
						withID(2).withTimestamp(baseTS.Time.Add(2 * time.Minute)),
					baseViolation.withDest("ns2", "svc2").withDstPort(443).
						withID(1).withTimestamp(baseTS.Time.Add(time.Minute)),
					baseViolation.withDest("ns2", "svc").withDstPort(80).
						withID(0),
				},
				ViolationCount: 3,
			},
		},
		{
			name: "scrape_new_and_old_violations",
			scraped: []ViolationRecord{
				// Existing violation with newer timestamp.
				baseViolation.withTimestamp(baseTS.Time.Add(time.Hour)),
				// New violation.
				baseViolation.withDest("ns2", "svc2").withDstPort(443).
					withTimestamp(baseTS.Time.Add(time.Minute)),
			},
			initialStatus: baseStatus,
			expectedStatus: WorkloadNetworkPolicyStatus{
				Violations: []ViolationRecord{
					// The existing violation keeps its id and gets the newer timestamp.
					baseViolation.withDest("ns2", "svc").withDstPort(80).
						withID(0).withTimestamp(baseTS.Time.Add(time.Hour)),
					// New violation gets a new id.
					baseViolation.withDest("ns2", "svc2").withDstPort(443).
						withID(2).withTimestamp(baseTS.Time.Add(time.Minute)),
				},
				// ViolationCount bumps for every observed record.
				ViolationCount: 3,
			},
		},
		{
			name: "trim_to_MaxViolationRecords",
			scraped: []ViolationRecord{
				baseViolation.withDest("ns2", "overflow").withDstPort(9999).
					withID(0).withTimestamp(baseTS.Time.Add(101 * time.Minute)),
			},
			initialStatus: func() WorkloadNetworkPolicyStatus {
				r := make([]ViolationRecord, maxViolationRecords)
				for i := range r {
					r[i] = baseViolation.withDest("ns2", fmt.Sprintf("svc-%d", i+1)).
						withDstPort(int32(i + 1)).
						withID(int64(i)).
						withTimestamp(baseTS.Time.Add(time.Duration(i+1) * time.Minute))
				}
				return WorkloadNetworkPolicyStatus{
					Violations:     r,
					ViolationCount: 100,
				}
			}(),
			expectedStatus: func() WorkloadNetworkPolicyStatus {
				r := make([]ViolationRecord, maxViolationRecords+1)
				for i := range r {
					r[i] = baseViolation.withDest("ns2", fmt.Sprintf("svc-%d", i+1)).
						withDstPort(int32(i + 1)).
						withID(int64(i)).
						withTimestamp(baseTS.Time.Add(time.Duration(i+1) * time.Minute))
				}
				// Replace the last entry with the overflow record.
				// The merge assigns ID = ViolationCount (100) before incrementing.
				r[maxViolationRecords] = baseViolation.withDest("ns2", "overflow").
					withDstPort(9999).
					withID(100).
					withTimestamp(baseTS.Time.Add(101 * time.Minute))
				slices.SortStableFunc(r, func(a, b ViolationRecord) int {
					return b.Timestamp.Time.Compare(a.Timestamp.Time)
				})
				return WorkloadNetworkPolicyStatus{
					Violations:     r[:maxViolationRecords],
					ViolationCount: 101,
				}
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.initialStatus.mergeScrapedViolations(tt.scraped)
			require.Equal(t, tt.expectedStatus, tt.initialStatus)
		})
	}
}

func TestClearAllowedViolations(t *testing.T) {
	base := mkViolation()

	protoTCP := corev1.ProtocolTCP
	port80 := intstr.FromInt32(80)

	tests := []struct {
		name       string
		violations []ViolationRecord
		template   networkingv1.NetworkPolicySpec
		expected   []ViolationRecord
	}{
		{
			name: "egress_with_namespace_match",
			violations: []ViolationRecord{
				base,
				base.withDest("ns3", "other").withDstPort(443),
			},
			template: networkingv1.NetworkPolicySpec{
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{corev1.LabelMetadataName: "ns2"},
								},
							},
						},
						Ports: []networkingv1.NetworkPolicyPort{
							{Protocol: &protoTCP, Port: &port80},
						},
					},
				},
			},
			expected: []ViolationRecord{
				base.withDest("ns3", "other").withDstPort(443),
			},
		},
		{
			name: "ingress_with_namespace_match",
			violations: []ViolationRecord{
				base,
				func() ViolationRecord {
					r := base
					r.Source = WorkloadRef{Namespace: "ns3", OwnerKind: "Deployment", OwnerName: "other"}
					return r
				}(),
			},
			template: networkingv1.NetworkPolicySpec{
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{corev1.LabelMetadataName: "ns1"},
								},
							},
						},
						Ports: []networkingv1.NetworkPolicyPort{
							{Protocol: &protoTCP, Port: &port80},
						},
					},
				},
			},
			expected: []ViolationRecord{
				base.withSource("ns3", "other"),
			},
		},
		{
			name: "egress_with_empty_namespace_selector_does_not_match",
			violations: []ViolationRecord{
				base,
			},
			template: networkingv1.NetworkPolicySpec{
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{NamespaceSelector: &metav1.LabelSelector{}},
						},
						Ports: []networkingv1.NetworkPolicyPort{
							{Protocol: &protoTCP, Port: &port80},
						},
					},
				},
			},
			// Synthetic rule has NamespaceSelector: {kubernetes.io/metadata.name: ns2};
			// template has empty NamespaceSelector {}. Strict equality fails.
			expected: []ViolationRecord{base},
		},
		{
			name: "egress_with_no_ports_does_not_match",
			violations: []ViolationRecord{
				base,
			},
			template: networkingv1.NetworkPolicySpec{
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{corev1.LabelMetadataName: "ns2"},
								},
							},
						},
					},
				},
			},
			// Synthetic rule has Ports: [{TCP, 80}]; template has no Ports. Strict equality fails.
			expected: []ViolationRecord{base},
		},
		{
			name: "egress_with_pod_selector_not_matched_conservative",
			violations: []ViolationRecord{
				base,
			},
			template: networkingv1.NetworkPolicySpec{
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{corev1.LabelMetadataName: "ns2"},
								},
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "allowed"},
								},
							},
						},
						Ports: []networkingv1.NetworkPolicyPort{
							{Protocol: &protoTCP, Port: &port80},
						},
					},
				},
			},
			// NOT cleared — PodSelector can't be resolved statically.
			expected: []ViolationRecord{base},
		},
		{
			name: "egress_with_ipblock_not_matched_conservative",
			violations: []ViolationRecord{
				base,
			},
			template: networkingv1.NetworkPolicySpec{
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								IPBlock: &networkingv1.IPBlock{
									CIDR: "10.0.0.0/8",
								},
							},
						},
						Ports: []networkingv1.NetworkPolicyPort{
							{Protocol: &protoTCP, Port: &port80},
						},
					},
				},
			},
			// NOT cleared — IPBlock can't be resolved without dest IP.
			expected: []ViolationRecord{base},
		},
		{
			name: "nil_template_leaves_violations_untouched",
			violations: []ViolationRecord{
				base,
			},
			template: networkingv1.NetworkPolicySpec{},
			expected: []ViolationRecord{base},
		},
		{
			name:       "empty_violations_no_panic",
			violations: nil,
			template:   networkingv1.NetworkPolicySpec{},
			expected:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wnp := &WorkloadNetworkPolicy{
				Spec: WorkloadNetworkPolicySpec{
					PolicyBackendSpec: PolicyBackendSpec{
						Backend:    PolicyBackendKubernetes,
						Kubernetes: &tt.template,
					},
				},
				Status: WorkloadNetworkPolicyStatus{
					Violations: tt.violations,
				},
			}
			wnp.clearAllowedViolations()
			require.Equal(t, tt.expected, wnp.Status.Violations)
		})
	}
}

func TestClearAllowedIstioViolations(t *testing.T) {
	base := mkViolation()

	istioWNP := func(rules []IstioAuthorizationPolicyRule) *WorkloadNetworkPolicy {
		return &WorkloadNetworkPolicy{
			Spec: WorkloadNetworkPolicySpec{
				PolicyBackendSpec: PolicyBackendSpec{
					Backend: PolicyBackendIstio,
					Istio: &IstioAuthorizationPolicySpec{
						Selector: metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "server"},
						},
						Rules: rules,
					},
				},
			},
		}
	}

	srcPolicy := func(principals ...string) IstioAuthorizationPolicyRule {
		return IstioAuthorizationPolicyRule{
			From: []IstioFrom{
				{Source: IstioSource{Principals: principals}},
			},
			To: []IstioTo{
				{Operation: IstioOperation{Ports: []string{"80"}}},
			},
		}
	}

	// appIdentity is the SPIFFE identity of the violation source in ns1.
	appIdentity := "spiffe://cluster.local/ns/ns1/sa/app-sa"
	appViolation := base.withSourceIdentity(appIdentity)

	tests := []struct {
		name      string
		rules     []IstioAuthorizationPolicyRule
		violation ViolationRecord
		expected  []ViolationRecord
	}{
		{
			name:      "matching_source_identity_clears",
			rules:     []IstioAuthorizationPolicyRule{srcPolicy(appIdentity)},
			violation: appViolation,
			expected:  nil,
		},
		{
			// Kyle's case: a rule allowing app-sa must not clear a violation
			// from other-sa in the same namespace, Istio would still deny it.
			name:      "same_namespace_different_principal_keeps",
			rules:     []IstioAuthorizationPolicyRule{srcPolicy(appIdentity)},
			violation: base.withSourceIdentity("spiffe://cluster.local/ns/ns1/sa/other-sa"),
			expected: []ViolationRecord{
				base.withSourceIdentity("spiffe://cluster.local/ns/ns1/sa/other-sa"),
			},
		},
		{
			// Without the source identity we cannot prove the rule allows the
			// source, so the violation is kept (fail-safe).
			name:      "unknown_source_identity_keeps_on_principal_rule",
			rules:     []IstioAuthorizationPolicyRule{srcPolicy(appIdentity)},
			violation: base,
			expected:  []ViolationRecord{base},
		},
		{
			// The canonical principal form carries no `spiffe://` scheme: the
			// backend strips it at ingestion, so both sides match exactly.
			name:      "canonical_prefix_free_identity_clears",
			rules:     []IstioAuthorizationPolicyRule{srcPolicy("cluster.local/ns/ns1/sa/app-sa")},
			violation: base.withSourceIdentity("cluster.local/ns/ns1/sa/app-sa"),
			expected:  nil,
		},
		{
			// A rule written with the `spiffe://` scheme cannot match the
			// canonical prefix-free identity: principals must follow the Istio
			// form. Keeps the violation (fail-safe).
			name:      "prefixed_rule_principal_keeps",
			rules:     []IstioAuthorizationPolicyRule{srcPolicy("spiffe://cluster.local/ns/ns1/sa/app-sa")},
			violation: base.withSourceIdentity("cluster.local/ns/ns1/sa/app-sa"),
			expected:  []ViolationRecord{base.withSourceIdentity("cluster.local/ns/ns1/sa/app-sa")},
		},
		{
			name:      "other_source_identity_keeps",
			rules:     []IstioAuthorizationPolicyRule{srcPolicy("spiffe://cluster.local/ns/other/sa/app-sa")},
			violation: appViolation,
			expected:  []ViolationRecord{appViolation},
		},
		{
			name:      "other_port_keeps",
			rules:     []IstioAuthorizationPolicyRule{srcPolicy(appIdentity).withPorts("8080")},
			violation: appViolation,
			expected:  []ViolationRecord{appViolation},
		},
		{
			name:      "port_range_match_clears",
			rules:     []IstioAuthorizationPolicyRule{srcPolicy(appIdentity).withPorts("80-90")},
			violation: appViolation,
			expected:  nil,
		},
		{
			name: "wildcard_principal_clears",
			rules: []IstioAuthorizationPolicyRule{
				{
					From: []IstioFrom{{Source: IstioSource{Principals: []string{"*"}}}},
					To:   []IstioTo{{Operation: IstioOperation{Ports: []string{"80"}}}},
				},
			},
			violation: base,
			expected:  nil,
		},
		{
			name: "empty_from_matches_any_source",
			rules: []IstioAuthorizationPolicyRule{
				{To: []IstioTo{{Operation: IstioOperation{Ports: []string{"80"}}}}},
			},
			violation: base,
			expected:  nil,
		},
		{
			name: "empty_to_matches_any_port",
			rules: []IstioAuthorizationPolicyRule{{From: []IstioFrom{{Source: IstioSource{Principals: []string{
				appIdentity,
			}}}}}},
			violation: appViolation,
			expected:  nil,
		},
		{
			name:      "nil_istio_spec_leaves_untouched",
			rules:     nil,
			violation: base,
			expected:  []ViolationRecord{base},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wnp := istioWNP(tt.rules)
			wnp.Status.Violations = []ViolationRecord{tt.violation}
			wnp.clearAllowedViolations()
			if tt.expected == nil {
				require.Empty(t, wnp.Status.Violations)
				return
			}
			require.Equal(t, tt.expected, wnp.Status.Violations)
		})
	}
}

// withPorts returns a copy of the rule with the given destination ports.
func (r IstioAuthorizationPolicyRule) withPorts(ports ...string) IstioAuthorizationPolicyRule {
	r.To = []IstioTo{{Operation: IstioOperation{Ports: ports}}}
	return r
}

func TestAcknowledgeViolationsFromAnnotations(t *testing.T) {
	now := metav1.NewTime(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))

	newViolation := func(id int64) ViolationRecord {
		return ViolationRecord{
			ID:        id,
			Timestamp: metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			Source: WorkloadRef{
				Namespace: "ns1",
				OwnerKind: "Deployment",
				OwnerName: "app",
			},
			Dest: WorkloadRef{
				Namespace: "ns2",
				OwnerKind: "Service",
				OwnerName: fmt.Sprintf("svc-%d", id),
			},
			Protocol:               corev1.ProtocolTCP,
			DstPort:                80,
			Action:                 "protect",
			DenyingPolicyNamespace: "ns1",
			DenyingPolicyName:      "deny-all",
		}
	}

	newAck := func(id int64, reason string, at metav1.Time) AcknowledgedViolationRecord {
		return AcknowledgedViolationRecord{
			Violation: newViolation(id), Reason: reason, AcknowledgedAt: at}
	}

	tests := []struct {
		name             string
		annotations      map[string]string
		violations       []ViolationRecord
		acknowledged     []AcknowledgedViolationRecord
		wantAnnotations  map[string]string
		wantViolations   []ViolationRecord
		wantAcknowledged []AcknowledgedViolationRecord
		wantReturned     []AcknowledgedViolationRecord
	}{
		{
			name:            "unrelated_annotations",
			annotations:     map[string]string{"unrelated.io/key": "value"},
			violations:      []ViolationRecord{newViolation(1)},
			wantAnnotations: map[string]string{"unrelated.io/key": "value"},
			wantViolations:  []ViolationRecord{newViolation(1)},
		},
		{
			name: "multiple_annotations_match_multiple_violations",
			annotations: map[string]string{
				ViolationAcknowledgePrefix + "1": "reason one",
				ViolationAcknowledgePrefix + "2": "reason two",
			},
			violations: []ViolationRecord{
				newViolation(1),
				newViolation(2),
			},
			wantAnnotations: map[string]string{},
			wantViolations:  []ViolationRecord{},
			wantAcknowledged: []AcknowledgedViolationRecord{
				newAck(1, "reason one", now),
				newAck(2, "reason two", now),
			},
			wantReturned: []AcknowledgedViolationRecord{
				newAck(1, "reason one", now),
				newAck(2, "reason two", now),
			},
		},
		{
			name: "partial_match_leaves_unacknowledged_violation",
			annotations: map[string]string{
				ViolationAcknowledgePrefix + "1":      "acknowledged",
				ViolationAcknowledgePrefix + "999":    "no match",
				ViolationAcknowledgePrefix + "random": "wrong key",
			},
			violations:   []ViolationRecord{newViolation(1)},
			acknowledged: []AcknowledgedViolationRecord{newAck(2, "acknowledged", now)},
			wantAnnotations: map[string]string{
				ViolationAcknowledgePrefix + "999":    "no match",
				ViolationAcknowledgePrefix + "random": "wrong key",
			},
			wantViolations: []ViolationRecord{},
			wantAcknowledged: []AcknowledgedViolationRecord{
				newAck(2, "acknowledged", now),
				newAck(1, "acknowledged", now),
			},
			wantReturned: []AcknowledgedViolationRecord{
				newAck(1, "acknowledged", now),
			},
		},
		{
			name: "acknowledge_with_empty_violations",
			annotations: map[string]string{
				ViolationAcknowledgePrefix + "1": "reason",
			},
			wantAnnotations: map[string]string{ViolationAcknowledgePrefix + "1": "reason"},
		},
		{
			name: "trims_acknowledged_violations_to_MaxViolationRecords",
			annotations: map[string]string{
				ViolationAcknowledgePrefix + "101": "acknowledged",
			},
			violations: []ViolationRecord{newViolation(101)},
			acknowledged: func() []AcknowledgedViolationRecord {
				r := make([]AcknowledgedViolationRecord, maxViolationRecords)
				for i := range r {
					r[i] = newAck(int64(i), "acknowledged", now)
				}
				return r
			}(),
			wantAnnotations: map[string]string{},
			wantViolations:  []ViolationRecord{},
			wantAcknowledged: func() []AcknowledgedViolationRecord {
				r := make([]AcknowledgedViolationRecord, maxViolationRecords+1)
				for i := range r {
					r[i] = newAck(int64(i), "acknowledged", now)
				}
				r[maxViolationRecords] = newAck(101, "acknowledged", now)
				slices.SortFunc(r, func(a, b AcknowledgedViolationRecord) int {
					return b.AcknowledgedAt.Time.Compare(a.AcknowledgedAt.Time)
				})
				return r[:maxViolationRecords]
			}(),
			wantReturned: []AcknowledgedViolationRecord{
				newAck(101, "acknowledged", now),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wnp := &WorkloadNetworkPolicy{
				Annotations: tt.annotations,
				Status: WorkloadNetworkPolicyStatus{
					Violations:             tt.violations,
					AcknowledgedViolations: tt.acknowledged,
				},
			}

			returned := wnp.acknowledgeViolationsFromAnnotations(now)

			require.Equal(t, tt.wantAnnotations, wnp.GetAnnotations())
			require.ElementsMatch(t, tt.wantViolations, wnp.Status.Violations)
			require.ElementsMatch(t, tt.wantAcknowledged, wnp.Status.AcknowledgedViolations)
			require.ElementsMatch(t, tt.wantReturned, returned)
		})
	}
}

func TestRecomputeStatus(t *testing.T) {
	now := metav1.NewTime(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))

	v1 := mkViolation().withTimestamp(now.Time.Add(-10 * time.Minute))
	v2 := mkViolation().withDest("ns2", "svc2").withDstPort(443).
		withTimestamp(now.Time.Add(-5 * time.Minute))

	t.Run("empty_status", func(t *testing.T) {
		wnp := &WorkloadNetworkPolicy{}
		ack := wnp.RecomputeStatus(nil, now)
		require.Empty(t, ack)
		require.Equal(t, int64(0), wnp.Status.ActiveViolationCount)
		require.Equal(t, int64(0), wnp.Status.ViolationCount)
	})

	t.Run("merge_and_acknowledge", func(t *testing.T) {
		wnp := &WorkloadNetworkPolicy{
			Annotations: map[string]string{
				ViolationAcknowledgePrefix + "0": "known issue",
			},
		}

		ack := wnp.RecomputeStatus([]ViolationRecord{v1, v2}, now)

		// ViolationCount should be 2.
		require.Equal(t, int64(2), wnp.Status.ViolationCount)
		// ActiveViolationCount is len(Violations).
		// v1 was acknowledged, so only v2 remains.
		require.Equal(t, int64(1), wnp.Status.ActiveViolationCount)
		require.Len(t, wnp.Status.Violations, 1)
		require.Equal(t, "svc2", wnp.Status.Violations[0].Dest.OwnerName)

		// v1 should be in acknowledged violations.
		require.Len(t, wnp.Status.AcknowledgedViolations, 1)
		require.Len(t, ack, 1)
		require.Equal(t, "known issue", ack[0].Reason)

		// ObservedGeneration should be set.
		require.Equal(t, wnp.Generation, wnp.Status.ObservedGeneration)
	})

	t.Run("merge_clear_acknowledge_order", func(t *testing.T) {
		// Create a violation that matches the template (will be cleared)
		// and one that doesn't.
		clearedV := mkViolation()
		keptV := mkViolation().withDest("ns3", "kept").withDstPort(8080)

		wnp := &WorkloadNetworkPolicy{
			Spec: WorkloadNetworkPolicySpec{
				PolicyBackendSpec: PolicyBackendSpec{
					Backend: PolicyBackendKubernetes,
					Kubernetes: &networkingv1.NetworkPolicySpec{
						Egress: []networkingv1.NetworkPolicyEgressRule{
							{
								To: []networkingv1.NetworkPolicyPeer{
									{
										NamespaceSelector: &metav1.LabelSelector{
											MatchLabels: map[string]string{
												corev1.LabelMetadataName: "ns2",
											},
										},
									},
								},
								Ports: []networkingv1.NetworkPolicyPort{
									{
										Protocol: &([]corev1.Protocol{corev1.ProtocolTCP}[0]),
										Port:     &([]intstr.IntOrString{intstr.FromInt32(80)}[0]),
									},
								},
							},
						},
					},
				},
			},
		}

		ack := wnp.RecomputeStatus([]ViolationRecord{clearedV, keptV}, now)

		require.Equal(t, int64(2), wnp.Status.ViolationCount)
		require.Equal(t, int64(1), wnp.Status.ActiveViolationCount)
		require.Len(t, wnp.Status.Violations, 1)
		require.Equal(t, "kept", wnp.Status.Violations[0].Dest.OwnerName)

		require.Empty(t, ack)
	})
}
