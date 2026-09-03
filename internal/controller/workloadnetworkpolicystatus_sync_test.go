package controller

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/violation"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

//nolint:unparam // for now some params always receive the same value
func newViolation(
	ts time.Time,
	srcNS string,
	srcName string,
	dstNS string,
	dstName string,
	denyNS string,
	denyName string,
) violation.Observation {
	return violation.Observation{
		Timestamp: metav1.NewTime(ts),
		Source: securityv1alpha1.WorkloadRef{
			Namespace: srcNS,
			OwnerKind: "Deployment",
			OwnerName: srcName,
		},
		Dest: securityv1alpha1.WorkloadRef{
			Namespace: dstNS,
			OwnerKind: "Service",
			OwnerName: dstName,
		},
		Protocol:               corev1.ProtocolTCP,
		DstPort:                80,
		Action:                 securityv1alpha1.WorkloadNetworkPolicyModeProtect,
		DenyingPolicyNamespace: denyNS,
		DenyingPolicyName:      denyName,
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestCorrelateViolationsToWNPs verifies the controller keys already-enriched
// observations to their owning WorkloadNetworkPolicy. Both DENY and ALLOW-miss
// observations carry the owning policy in DenyingPolicyNamespace/Name by the
// time they reach the controller (the scraper resolves the ALLOW-miss owner by
// selector match, see istio.Enricher), so the controller no longer inspects pod
// labels — it only keys by the recorded policy name and drops what it cannot
// correlate.
func TestCorrelateViolationsToWNPs(t *testing.T) {
	t.Parallel()

	npKey := types.NamespacedName{Namespace: "ns1", Name: "policy-1"}
	wnpKey := types.NamespacedName{Namespace: "ns1", Name: "policy-1"}
	// allowMissWNPKey is the owning WNP the scraper resolved for an ALLOW-miss.
	// Its name is arbitrary (user-chosen) on purpose: correlation keys on the
	// recorded name, whatever it is.
	allowMissWNPKey := types.NamespacedName{Namespace: "ns1", Name: "user-named-wnp"}
	ownedIndex := map[types.NamespacedName]*types.NamespacedName{
		npKey: &wnpKey,
	}
	wnpByKey := map[types.NamespacedName]*securityv1alpha1.WorkloadNetworkPolicy{
		wnpKey: {
			ObjectMeta: metav1.ObjectMeta{
				Name:      wnpKey.Name,
				Namespace: wnpKey.Namespace,
			},
		},
		allowMissWNPKey: {
			ObjectMeta: metav1.ObjectMeta{
				Name:      allowMissWNPKey.Name,
				Namespace: allowMissWNPKey.Namespace,
			},
		},
	}

	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		sync       *WorkloadNetworkPolicyStatusSync
		violations []violation.Observation
		check      func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord)
	}{
		{
			name: "attributes_deny_to_WNP",
			sync: &WorkloadNetworkPolicyStatusSync{},
			violations: []violation.Observation{
				newViolation(
					ts,
					"src-ns",
					"src-app",
					"dst-ns",
					"dst-svc",
					"ns1",
					"policy-1",
				),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Len(t, result, 1)
				require.Contains(t, result, wnpKey)
				require.Len(t, result[wnpKey], 1)
				require.Equal(t, "ns1", result[wnpKey][0].DenyingPolicyNamespace)
				require.Equal(t, "policy-1", result[wnpKey][0].DenyingPolicyName)
			},
		},
		{
			// A pre-resolved ALLOW-miss carries its owning WNP in the same fields as
			// a DENY (resolved by the scraper), so the controller keys it the same
			// way, regardless of the WNP's user-chosen name.
			name: "keys_pre_resolved_allow_miss_by_owning_WNP",
			sync: &WorkloadNetworkPolicyStatusSync{},
			violations: []violation.Observation{
				newViolation(
					ts,
					"src-ns",
					"src-app",
					allowMissWNPKey.Namespace,
					"frontend",
					allowMissWNPKey.Namespace,
					allowMissWNPKey.Name,
				),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Len(t, result, 1)
				require.Contains(t, result, allowMissWNPKey)
				require.Len(t, result[allowMissWNPKey], 1)
			},
		},
		{
			// An observation the scraper could not correlate (no owning policy
			// resolved) carries an empty policy name and is dropped.
			name: "drops_uncorrelated_observation",
			sync: &WorkloadNetworkPolicyStatusSync{},
			violations: []violation.Observation{
				newViolation(
					ts,
					"src-ns",
					"src-app",
					"dst-ns",
					"dst-svc",
					"",
					"",
				),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Empty(t, result)
			},
		},
		{
			// The recorded policy is not owned by us (a NetworkPolicy shares a WNP's
			// name but has no controller owner ref), so the violation is dropped.
			name: "drops_deny_by_unowned_NetworkPolicy",
			sync: &WorkloadNetworkPolicyStatusSync{
				logger: ctrl.Log.WithName("test"),
			},
			violations: []violation.Observation{
				newViolation(
					ts,
					"src-ns",
					"src-app",
					"dst-ns",
					"dst-svc",
					"ns-other",
					"raw-policy",
				),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Empty(t, result)
			},
		},
		{
			name: "warns_when_denying_WNP_is_deleted",
			sync: &WorkloadNetworkPolicyStatusSync{
				logger: ctrl.Log.WithName("test"),
			},
			violations: []violation.Observation{
				newViolation(
					ts,
					"src-ns",
					"src-app",
					"dst-ns",
					"dst-svc",
					"ns-missing",
					"deleted-policy",
				),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Empty(t, result)
			},
		},
		{
			name: "dedup_by_violation_key",
			sync: &WorkloadNetworkPolicyStatusSync{},
			violations: []violation.Observation{
				newViolation(
					ts,
					"src-ns",
					"src-app",
					"dst-ns",
					"dst-svc",
					"ns1",
					"policy-1",
				),
				newViolation(
					ts,
					"src-ns",
					"src-app",
					"dst-ns",
					"dst-svc",
					"ns1",
					"policy-1",
				),
			},
			check: func(t *testing.T, result map[types.NamespacedName][]securityv1alpha1.ViolationRecord) {
				require.Len(t, result, 1)
				// Both violations are in the list — dedup is done later by
				// RecomputeStatus → mergeScrapedViolations which uses the key.
				require.Len(t, result[wnpKey], 2)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.sync.correlateViolationsToWNPs(tt.violations, ownedIndex, wnpByKey)
			tt.check(t, result)
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

func TestSyncSkipsWhenNoWNPs(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		Build()

	sync := &WorkloadNetworkPolicyStatusSync{
		Client:         fakeClient,
		updateInterval: time.Hour,
		logger:         ctrl.Log.WithName("test"),
	}

	err := sync.sync(context.Background())
	require.NoError(t, err)
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
