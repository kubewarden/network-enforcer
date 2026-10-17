package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/violation"
	"github.com/kubewarden/network-enforcer/internal/workload"
)

const attributionTestNS = "ns1"

func deploymentRef(name string) securityv1alpha1.WorkloadRef {
	return securityv1alpha1.WorkloadRef{
		Namespace: attributionTestNS,
		OwnerKind: securityv1alpha1.WorkloadKindDeployment,
		OwnerName: name,
	}
}

// offClusterPeer is how an external endpoint looks once it reaches the
// controller: no namespace, no workload kind, only an address.
func offClusterPeer() securityv1alpha1.WorkloadRef {
	return securityv1alpha1.WorkloadRef{OwnerName: "203.0.113.10"}
}

func newTargetedWNP(name, target string, direction networkingv1.PolicyType) *securityv1alpha1.WorkloadNetworkPolicy {
	wnp := newTestWNP(name, attributionTestNS)
	wnp.Spec.TargetRef = securityv1alpha1.WorkloadTargetRef{
		Kind: securityv1alpha1.WorkloadKindDeployment,
		Name: target,
	}
	wnp.Spec.Direction = direction
	wnp.Spec.Kubernetes.PolicyTypes = []networkingv1.PolicyType{direction}
	return wnp
}

func newAttributionObservation(
	direction networkingv1.PolicyType,
	src, dst securityv1alpha1.WorkloadRef,
	reportedPolicy string,
) violation.Observation {
	obs := violation.Observation{
		Provider:  securityv1alpha1.PolicyBackendKubernetes,
		Direction: direction,
		Timestamp: metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		Source:    src,
		Dest:      dst,
		Protocol:  corev1.ProtocolTCP,
		DstPort:   443,
		Action:    securityv1alpha1.WorkloadNetworkPolicyModeProtect,
	}
	if reportedPolicy != "" {
		obs.DenyingPolicyNamespace = attributionTestNS
		obs.DenyingPolicyName = reportedPolicy
	}
	return obs
}

// attributionFixture is the cluster state shared by the attribution tests:
//
//   - frontend-egress   targets Deployment/frontend Egress, renders NetworkPolicies
//     frontend-egress and renamed-np (both controlled by it).
//   - frontend-ingress  targets Deployment/frontend Ingress, no NetworkPolicy.
//   - backend-ingress   targets Deployment/backend Ingress, no NetworkPolicy
//     (monitor mode, or an Istio AuthorizationPolicy with the WNP name).
//   - canary-egress     targets Deployment/canary Egress, renders NetworkPolicy
//     canary-egress. Its selector overlapping frontend's is what makes the data
//     plane report it for frontend traffic.
//   - dup-a, dup-b      both target Deployment/dup Egress.
//   - web-ingress       targets Deployment/web Ingress. A NetworkPolicy also
//     named web-ingress exists, but is owned by canary-egress: it must not be
//     mistaken for web-ingress's AuthorizationPolicy in an Istio report.
//   - foreign-np        a NetworkPolicy not managed by any WNP.
//
// Deployment/orphan has no WNP at all.
type attributionFixture struct {
	client     client.WithWatch
	ownedIndex map[types.NamespacedName]*types.NamespacedName
	wnpByKey   map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy
}

func newAttributionFixture(t *testing.T) attributionFixture {
	t.Helper()

	frontendEgress := newTargetedWNP("frontend-egress", "frontend", networkingv1.PolicyTypeEgress)
	frontendIngress := newTargetedWNP("frontend-ingress", "frontend", networkingv1.PolicyTypeIngress)
	backendIngress := newTargetedWNP("backend-ingress", "backend", networkingv1.PolicyTypeIngress)
	canaryEgress := newTargetedWNP("canary-egress", "canary", networkingv1.PolicyTypeEgress)
	dupA := newTargetedWNP("dup-a", "dup", networkingv1.PolicyTypeEgress)
	dupB := newTargetedWNP("dup-b", "dup", networkingv1.PolicyTypeEgress)
	webIngress := newTargetedWNP("web-ingress", "web", networkingv1.PolicyTypeIngress)

	renamedNP := newOwnedNetworkPolicy(frontendEgress)
	renamedNP.Name = "renamed-np"
	namesakeNP := newOwnedNetworkPolicy(canaryEgress)
	namesakeNP.Name = webIngress.Name
	foreignNP := &networkingv1.NetworkPolicy{Name: "foreign-np", Namespace: attributionTestNS}

	wnps := []*securityv1alpha1.WorkloadNetworkPolicy{
		frontendEgress, frontendIngress, backendIngress, canaryEgress, dupA, dupB, webIngress,
	}
	objs := []client.Object{
		newOwnedNetworkPolicy(frontendEgress), renamedNP, newOwnedNetworkPolicy(canaryEgress), namesakeNP, foreignNP,
	}
	wnpByKey := make(map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy, len(wnps))
	for _, wnp := range wnps {
		objs = append(objs, wnp)
		wnpByKey[wnp.NamespacedName()] = wnp
	}

	c := fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithObjects(objs...).
		WithIndex(&securityv1alpha1.WorkloadNetworkPolicy{}, workload.WNPTargetIndexField, workload.IndexWNPByTarget).
		Build()

	ownedIndex, err := (&WorkloadNetworkPolicyStatusSync{Client: c}).buildOwnershipIndex(t.Context(), wnpByKey)
	require.NoError(t, err)

	return attributionFixture{client: c, ownedIndex: ownedIndex, wnpByKey: wnpByKey}
}

func wnpKey(name string) types.NamespacedName {
	return types.NamespacedName{Namespace: attributionTestNS, Name: name}
}

// TestAttributeViolation covers each branch of the attribution chain. The
// targetRef lookups are counted through an interceptor so a case can tell
// whether it was resolved by the reported policy or by the targetRef index.
func TestAttributeViolation(t *testing.T) {
	t.Parallel()

	egress, ingress := networkingv1.PolicyTypeEgress, networkingv1.PolicyTypeIngress
	frontend, backend := deploymentRef("frontend"), deploymentRef("backend")
	webIstioReport := newAttributionObservation(ingress, frontend, deploymentRef("web"), "web-ingress")
	webIstioReport.Provider = securityv1alpha1.PolicyBackendIstio

	tests := []struct {
		name string
		obs  violation.Observation
		// excludeFromSnapshot simulates a WNP present in the cache but not in
		// this cycle's listed snapshot.
		excludeFromSnapshot string
		failLookup          bool
		wantWNP             string
		wantReason          string
		wantLookup          bool
		wantDisagreement    bool
	}{
		// Step 1: reported enforcing object, verified.
		{
			name:    "reported_networkpolicy_owned_by_wnp_targeting_subject",
			obs:     newAttributionObservation(egress, frontend, backend, "frontend-egress"),
			wantWNP: "frontend-egress",
		},
		{
			name:    "reported_networkpolicy_attributed_to_its_owner_not_its_name",
			obs:     newAttributionObservation(egress, frontend, backend, "renamed-np"),
			wantWNP: "frontend-egress",
		},
		{
			name:    "reported_wnp_without_backing_networkpolicy",
			obs:     newAttributionObservation(ingress, frontend, backend, "backend-ingress"),
			wantWNP: "backend-ingress",
		},
		{
			// The reported AuthorizationPolicy is resolved by WNP name; a
			// NetworkPolicy sharing its name but owned by canary-egress must not be
			// taken as its owner (that would count a false disagreement).
			name:    "istio_report_ignores_namesake_networkpolicy",
			obs:     webIstioReport,
			wantWNP: "web-ingress",
		},
		// Step 2: targetRef index.
		{
			name:       "no_reported_policy",
			obs:        newAttributionObservation(egress, frontend, backend, ""),
			wantWNP:    "frontend-egress",
			wantLookup: true,
		},
		{
			name:             "reported_owner_targets_other_workload_subject_wins",
			obs:              newAttributionObservation(egress, frontend, backend, "canary-egress"),
			wantWNP:          "frontend-egress",
			wantLookup:       true,
			wantDisagreement: true,
		},
		{
			name:       "reported_owner_targets_subject_in_other_direction",
			obs:        newAttributionObservation(egress, frontend, backend, "frontend-ingress"),
			wantWNP:    "frontend-egress",
			wantLookup: true,
		},
		{
			name:       "reported_networkpolicy_not_managed_by_a_wnp",
			obs:        newAttributionObservation(egress, frontend, backend, "foreign-np"),
			wantWNP:    "frontend-egress",
			wantLookup: true,
		},
		{
			name:       "reported_policy_unknown",
			obs:        newAttributionObservation(egress, frontend, backend, "deleted-policy"),
			wantWNP:    "frontend-egress",
			wantLookup: true,
		},
		// Step 3: explicitly unattributed.
		{
			name:       "no_wnp_targets_subject",
			obs:        newAttributionObservation(egress, deploymentRef("orphan"), backend, ""),
			wantReason: unattributedReasonNoTargetPolicy,
			wantLookup: true,
		},
		{
			name:             "disagreement_and_no_wnp_targets_subject",
			obs:              newAttributionObservation(egress, deploymentRef("orphan"), backend, "canary-egress"),
			wantReason:       unattributedReasonNoTargetPolicy,
			wantLookup:       true,
			wantDisagreement: true,
		},
		{
			name:       "duplicate_wnps_target_subject",
			obs:        newAttributionObservation(egress, deploymentRef("dup"), backend, ""),
			wantReason: unattributedReasonDuplicateTargetPolicy,
			wantLookup: true,
		},
		{
			name:       "targetref_lookup_fails",
			obs:        newAttributionObservation(egress, frontend, backend, ""),
			failLookup: true,
			wantReason: unattributedReasonLookupFailed,
			wantLookup: true,
		},
		{
			name:                "target_wnp_not_in_snapshot",
			obs:                 newAttributionObservation(egress, frontend, backend, ""),
			excludeFromSnapshot: "frontend-egress",
			wantReason:          unattributedReasonNoTargetPolicy,
			wantLookup:          true,
		},
		{
			// A verified reported policy is not trusted without a subject to
			// check it against.
			name:       "unknown_direction",
			obs:        newAttributionObservation("", frontend, backend, "frontend-egress"),
			wantReason: unattributedReasonUnknownSubject,
		},
		{
			// e.g. an Istio destination pod the enricher could not resolve.
			name: "subject_not_resolved_to_workload",
			obs: newAttributionObservation(ingress, frontend,
				securityv1alpha1.WorkloadRef{Namespace: attributionTestNS, OwnerName: "backend-7d9f-x2x"},
				"backend-ingress"),
			wantReason: unattributedReasonUnknownSubject,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fx := newAttributionFixture(t)

			if tt.excludeFromSnapshot != "" {
				delete(fx.wnpByKey, wnpKey(tt.excludeFromSnapshot))
			}

			lookups := 0
			c := interceptor.NewClient(fx.client, interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if _, ok := list.(*securityv1alpha1.WorkloadNetworkPolicyList); ok {
						lookups++
						if tt.failLookup {
							return errors.New("cache unavailable")
						}
					}
					return c.List(ctx, list, opts...)
				},
			})

			m := newAttributionMetrics()
			r := &WorkloadNetworkPolicyStatusSync{Client: c, logger: ctrl.Log.WithName("test"), metrics: m}

			gotKey, gotReason := r.attributeViolation(t.Context(), tt.obs, fx.ownedIndex, fx.wnpByKey)

			if tt.wantWNP != "" {
				require.Empty(t, gotReason)
				require.Equal(t, wnpKey(tt.wantWNP), gotKey)
			} else {
				require.Equal(t, tt.wantReason, gotReason)
				require.Equal(t, types.NamespacedName{}, gotKey)
			}
			require.Equal(t, tt.wantLookup, lookups > 0, "targetRef lookup performed")

			wantDisagreements := 0.0
			if tt.wantDisagreement {
				wantDisagreements = 1
			}
			require.InDelta(t, wantDisagreements, testutil.ToFloat64(m.disagreements.WithLabelValues(
				string(tt.obs.Provider), string(tt.obs.Direction))), 0)
		})
	}
}

// TestCorrelateViolationsToWNPs verifies attributed observations are grouped
// under their WNP with the record naming that WNP, and unattributed ones are
// dropped from status and counted.
func TestCorrelateViolationsToWNPs(t *testing.T) {
	t.Parallel()

	fx := newAttributionFixture(t)
	m := newAttributionMetrics()
	r := &WorkloadNetworkPolicyStatusSync{Client: fx.client, logger: ctrl.Log.WithName("test"), metrics: m}

	egress := networkingv1.PolicyTypeEgress
	frontend, backend := deploymentRef("frontend"), deploymentRef("backend")
	observations := []violation.Observation{
		newAttributionObservation(egress, frontend, backend, "frontend-egress"),
		newAttributionObservation(egress, frontend, backend, "frontend-egress"),
		newAttributionObservation(egress, frontend, backend, "canary-egress"),
		newAttributionObservation(egress, deploymentRef("orphan"), backend, ""),
		newAttributionObservation(egress, deploymentRef("dup"), backend, ""),
	}

	result := r.correlateViolationsToWNPs(t.Context(), observations, fx.ownedIndex, fx.wnpByKey)

	require.Len(t, result, 1)
	records := result[wnpKey("frontend-egress")]
	// Dedup by key happens later in RecomputeStatus, so all three are here.
	require.Len(t, records, 3)
	for _, rec := range records {
		require.Equal(t, attributionTestNS, rec.DenyingPolicyNamespace)
		require.Equal(t, "frontend-egress", rec.DenyingPolicyName,
			"the record names the WNP it is attributed to, not the reported object")
	}

	provider := string(securityv1alpha1.PolicyBackendKubernetes)
	require.InDelta(t, 1, testutil.ToFloat64(m.unattributed.WithLabelValues(
		provider, string(egress), unattributedReasonNoTargetPolicy)), 0)
	require.InDelta(t, 1, testutil.ToFloat64(m.unattributed.WithLabelValues(
		provider, string(egress), unattributedReasonDuplicateTargetPolicy)), 0)
	require.InDelta(t, 1, testutil.ToFloat64(m.disagreements.WithLabelValues(provider, string(egress))), 0)
}

// TestAttributeViolationOffClusterEgressPeer is a regression test: the subject
// of an egress violation is the source workload, so a destination outside the
// cluster (no namespace, no workload) must not prevent attribution.
func TestAttributeViolationOffClusterEgressPeer(t *testing.T) {
	t.Parallel()

	egress := networkingv1.PolicyTypeEgress
	frontend := deploymentRef("frontend")

	tests := []struct {
		name string
		obs  violation.Observation
	}{
		{
			name: "reported_policy",
			obs:  newAttributionObservation(egress, frontend, offClusterPeer(), "frontend-egress"),
		},
		{
			name: "no_reported_policy",
			obs:  newAttributionObservation(egress, frontend, offClusterPeer(), ""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fx := newAttributionFixture(t)
			m := newAttributionMetrics()
			r := &WorkloadNetworkPolicyStatusSync{Client: fx.client, logger: ctrl.Log.WithName("test"), metrics: m}

			result := r.correlateViolationsToWNPs(
				t.Context(), []violation.Observation{tt.obs}, fx.ownedIndex, fx.wnpByKey)

			records := result[wnpKey("frontend-egress")]
			require.Len(t, records, 1)
			require.Equal(t, offClusterPeer(), records[0].Dest)
			require.Equal(t, 0, testutil.CollectAndCount(m.unattributed))
		})
	}
}

func TestProcessWorkloadNetworkPolicy_TwoPhasePatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	wnp := newTestWNP("policy-1", "ns1")
	// Add an acknowledge annotation for one of the violations.
	wnp.Annotations = map[string]string{
		securityv1alpha1.ViolationAcknowledgePrefix + "0": "known issue",
	}

	ownedNP := newOwnedNetworkPolicy(wnp)

	s := newTestScheme()
	statusObj := &securityv1alpha1.WorkloadNetworkPolicy{}
	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(statusObj).
		WithObjects(wnp, ownedNP).
		Build()

	sync := &WorkloadNetworkPolicyStatusSync{
		Client:         fakeClient,
		updateInterval: time.Hour,
		logger:         ctrl.Log.WithName("test"),
	}

	violations := []securityv1alpha1.ViolationRecord{
		{
			Timestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
			Source: securityv1alpha1.WorkloadRef{
				Namespace: "src-ns", OwnerKind: "Deployment", OwnerName: "app",
			},
			Dest: securityv1alpha1.WorkloadRef{
				Namespace: "dst-ns", OwnerKind: "Service", OwnerName: "svc",
			},
			Protocol:               corev1.ProtocolTCP,
			DstPort:                80,
			Action:                 "protect",
			DenyingPolicyNamespace: "ns1",
			DenyingPolicyName:      "policy-1",
		},
	}

	err := sync.processWorkloadNetworkPolicy(context.Background(), wnp, violations)
	require.NoError(t, err)

	// Verify the status was written.
	var updatedWNP securityv1alpha1.WorkloadNetworkPolicy
	err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "ns1", Name: "policy-1"}, &updatedWNP)
	require.NoError(t, err)
	require.Equal(t, int64(1), updatedWNP.Status.ViolationCount)
	require.Equal(t, int64(0), updatedWNP.Status.ActiveViolationCount) // acknowledged

	// The acknowledge annotation should have been consumed.
	_, exists := updatedWNP.Annotations[securityv1alpha1.ViolationAcknowledgePrefix+"0"]
	require.False(t, exists, "acknowledge annotation should be removed")
}

func TestBuildOwnershipIndex(t *testing.T) {
	t.Parallel()

	wnp1 := newTestWNP("policy-1", "ns1")
	wnp2 := newTestWNP("policy-2", "ns2")

	ownedNP1 := newOwnedNetworkPolicy(wnp1)
	ownedNP2 := newOwnedNetworkPolicy(wnp2)
	// A NetworkPolicy with no owner reference.
	unownedNP := &networkingv1.NetworkPolicy{
		Name:      "raw-policy",
		Namespace: "ns1",
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithObjects(wnp1, wnp2, ownedNP1, ownedNP2, unownedNP).
		Build()

	wnpByKey := map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy{
		{Namespace: "ns1", Name: "policy-1"}: wnp1,
		{Namespace: "ns2", Name: "policy-2"}: wnp2,
	}

	sync := &WorkloadNetworkPolicyStatusSync{Client: fakeClient}
	index, err := sync.buildOwnershipIndex(context.Background(), wnpByKey)
	require.NoError(t, err)

	// Owned policies should be in the index.
	require.Equal(t, types.NamespacedName{Namespace: "ns1", Name: "policy-1"},
		*index[types.NamespacedName{Namespace: "ns1", Name: "policy-1"}])
	require.Equal(t, types.NamespacedName{Namespace: "ns2", Name: "policy-2"},
		*index[types.NamespacedName{Namespace: "ns2", Name: "policy-2"}])

	// Unowned policy should be in the index but the owner should be nil
	owner, exists := index[types.NamespacedName{Namespace: "ns1", Name: "raw-policy"}]
	require.True(t, exists)
	require.Nil(t, owner)
}

// TestSyncCountsUnattributedWhenNoWNPs verifies that observations are drained
// and counted as unattributed even when no WorkloadNetworkPolicy exists.
func TestSyncCountsUnattributedWhenNoWNPs(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithIndex(&securityv1alpha1.WorkloadNetworkPolicy{}, workload.WNPTargetIndexField, workload.IndexWNPByTarget).
		Build()

	m := newAttributionMetrics()
	sync := newTestWorkloadNetworkStatusSync(fakeClient)
	sync.metrics = m
	obs := newAttributionObservation(
		networkingv1.PolicyTypeEgress, deploymentRef("frontend"), offClusterPeer(), "")
	sync.violationBuffer.Record(obs)

	require.NoError(t, sync.sync(t.Context()))

	require.Empty(t, sync.violationBuffer.Drain(), "buffer should have been drained")
	require.InDelta(t, 1, testutil.ToFloat64(m.unattributed.WithLabelValues(
		string(obs.Provider), string(obs.Direction), unattributedReasonNoTargetPolicy)), 0)
}

// TestNewWorkloadNetworkPolicyStatusSync validates config.
func TestNewWorkloadNetworkPolicyStatusSync(t *testing.T) {
	t.Parallel()

	_, err := NewWorkloadNetworkPolicyStatusSync(nil, &WorkloadNetworkPolicyStatusSyncConfig{
		UpdateInterval: 0,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid update interval")
}

func TestSyncClearsViolationsWithNoNewScrapedViolations(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	tcp := corev1.ProtocolTCP
	port80 := intstr.FromInt32(80)

	wnp := newTestWNP("policy-1", "ns1")
	// Add an egress rule to the policy template that permits the traffic
	// that was previously denied and recorded as a violation.
	wnp.Spec.Kubernetes.Egress = []networkingv1.NetworkPolicyEgressRule{
		{
			To: []networkingv1.NetworkPolicyPeer{
				{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							corev1.LabelMetadataName: "dst-ns",
						},
					},
				},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{
					Protocol: &tcp,
					Port:     &port80,
				},
			},
		},
	}

	// Pre-populate status with a violation that matches the rule above.
	wnp.Status = securityv1alpha1.WorkloadNetworkPolicyStatus{
		ViolationCount:       1,
		ActiveViolationCount: 1,
		Violations: []securityv1alpha1.ViolationRecord{
			{
				ID:        0,
				Timestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
				Source: securityv1alpha1.WorkloadRef{
					Namespace: "src-ns", OwnerKind: "Deployment", OwnerName: "app",
				},
				Dest: securityv1alpha1.WorkloadRef{
					Namespace: "dst-ns", OwnerKind: "Service", OwnerName: "svc",
				},
				Protocol:               corev1.ProtocolTCP,
				DstPort:                80,
				Action:                 "protect",
				DenyingPolicyNamespace: "ns1",
				DenyingPolicyName:      "policy-1",
			},
		},
	}

	ownedNP := newOwnedNetworkPolicy(wnp)

	s := newTestScheme()
	statusObj := &securityv1alpha1.WorkloadNetworkPolicy{}
	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(statusObj).
		WithObjects(wnp, ownedNP).
		Build()

	sync := newTestWorkloadNetworkStatusSync(fakeClient)

	require.NoError(t, sync.sync(t.Context()))

	var updatedWNP securityv1alpha1.WorkloadNetworkPolicy
	require.NoError(t, fakeClient.Get(
		context.Background(),
		types.NamespacedName{Namespace: "ns1", Name: "policy-1"},
		&updatedWNP,
	))

	// The violation should have been cleared because it matches a rule in
	// the current policy template (clearAllowedViolations ran even though
	// no new violations were scraped).
	require.Equal(t, int64(1), updatedWNP.Status.ViolationCount,
		"ViolationCount should still be 1 (total observed)")
	require.Equal(t, int64(0), updatedWNP.Status.ActiveViolationCount,
		"ActiveViolationCount should be 0 after clearing")
	require.Empty(t, updatedWNP.Status.Violations,
		"Violations should be empty — the matching rule cleared it")
}

// TestTwoPhasePatchConflict simulates a scenario where an annotation is
// modified between the status patch and the metadata patch. Both patches
// use MergeFrom so the annotation should survive.
func TestTwoPhasePatchConflict(t *testing.T) {
	t.Parallel()

	// Start with a WNP that has a pre-existing annotation.
	wnp := newTestWNP("conflict-policy", "ns1")
	wnp.Annotations = map[string]string{
		"existing.io/key": "original-value",
	}
	ownedNP := newOwnedNetworkPolicy(wnp)

	s := newTestScheme()
	statusObj := &securityv1alpha1.WorkloadNetworkPolicy{}
	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(statusObj).
		WithObjects(wnp, ownedNP).
		Build()

	sync := newTestWorkloadNetworkStatusSync(fakeClient)

	violations := []securityv1alpha1.ViolationRecord{
		{
			Timestamp: metav1.NewTime(time.Now()),
			Source: securityv1alpha1.WorkloadRef{
				Namespace: "ns1", OwnerKind: "Deployment", OwnerName: "app",
			},
			Dest: securityv1alpha1.WorkloadRef{
				Namespace: "ns2", OwnerKind: "Service", OwnerName: "svc",
			},
			Protocol:               corev1.ProtocolTCP,
			DstPort:                80,
			Action:                 "protect",
			DenyingPolicyNamespace: "ns1",
			DenyingPolicyName:      "conflict-policy",
		},
	}

	require.NoError(t, sync.processWorkloadNetworkPolicy(t.Context(), wnp, violations))

	// The existing annotation should still be present.
	var updatedWNP securityv1alpha1.WorkloadNetworkPolicy
	require.NoError(t, fakeClient.Get(
		context.Background(),
		types.NamespacedName{Namespace: "ns1", Name: "conflict-policy"},
		&updatedWNP,
	))
	require.Equal(t, "original-value", updatedWNP.Annotations["existing.io/key"])
	// Status should also be updated.
	require.Equal(t, int64(1), updatedWNP.Status.ActiveViolationCount)
}
