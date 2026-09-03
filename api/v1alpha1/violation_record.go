package v1alpha1

import (
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// maxViolationRecords is the maximum number of ViolationRecords and
// AcknowledgedViolationRecords kept in status.
const maxViolationRecords = 100

// annotationInfo groups an annotation key with its acknowledge-reason pair.
type annotationInfo struct {
	annotationKey string
	reason        string
}

// ViolationRecordKey is the dedup key for recognising the same logical violation across scrapes.
type ViolationRecordKey struct {
	SrcNamespace           string
	SrcOwnerKind           string
	SrcOwnerName           string
	SrcIdentity            string
	DstNamespace           string
	DstOwnerKind           string
	DstOwnerName           string
	DstIdentity            string
	Protocol               string
	DstPort                int32
	Action                 WorkloadNetworkPolicyMode
	DenyingPolicyNamespace string
	DenyingPolicyName      string
}

// Key returns the dedup key for a ViolationRecord.
func (v ViolationRecord) Key() ViolationRecordKey {
	return ViolationRecordKey{
		SrcNamespace:           v.Source.Namespace,
		SrcOwnerKind:           string(v.Source.OwnerKind),
		SrcOwnerName:           v.Source.OwnerName,
		SrcIdentity:            v.Source.Identity,
		DstNamespace:           v.Dest.Namespace,
		DstOwnerKind:           string(v.Dest.OwnerKind),
		DstOwnerName:           v.Dest.OwnerName,
		DstIdentity:            v.Dest.Identity,
		Protocol:               string(v.Protocol),
		DstPort:                v.DstPort,
		Action:                 v.Action,
		DenyingPolicyNamespace: v.DenyingPolicyNamespace,
		DenyingPolicyName:      v.DenyingPolicyName,
	}
}

// ViolationInfo holds the details of a single network policy violation without
// the controller-assigned ID. Backend scrapers produce observations in this
// shape (see violation.Observation); the controller assigns the ID
// when it persists the record into wnp.Status.Violations.
// +kubebuilder:object:generate=true
type ViolationInfo struct {
	// Timestamp is when the violation last occurred.
	Timestamp metav1.Time `json:"timestamp"`
	// Source is the workload that initiated the traffic.
	// +optional
	Source WorkloadRef `json:"source,omitempty"`
	// Dest is the workload that received the traffic.
	// +optional
	Dest WorkloadRef `json:"dest,omitempty"`
	// Protocol is the L4 protocol (TCP, UDP).
	Protocol corev1.Protocol `json:"protocol"`
	// DstPort is the destination port. 0 when unavailable.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	// +optional
	DstPort int32 `json:"dstPort,omitempty"`
	// Action is the enforcement action taken (monitor or protect).
	Action WorkloadNetworkPolicyMode `json:"action"`
	// DenyingPolicyNamespace is the namespace of the WorkloadNetworkPolicy this
	// violation belongs to. For a DENY it is the policy that denied the flow; for
	// an ALLOW-miss (which carries no denying policy on the wire) the scraper
	// resolves the owning WorkloadNetworkPolicy by matching the destination pod's
	// labels against WNP selectors and records it here (see istio.Enricher).
	// +optional
	DenyingPolicyNamespace string `json:"denyingPolicyNamespace,omitempty"`
	// DenyingPolicyName is the name of the WorkloadNetworkPolicy this violation
	// belongs to. For a DENY it is the policy that denied the flow; for an
	// ALLOW-miss it is the owning WorkloadNetworkPolicy resolved by selector match
	// (see DenyingPolicyNamespace). The controller keys the violation to its WNP
	// by this name for both cases; Action (monitor vs protect) distinguishes them.
	// +optional
	DenyingPolicyName string `json:"denyingPolicyName,omitempty"`
}

// ViolationRecord holds the details of a single network policy violation.
// It embeds ViolationInfo (the violation without the ID) so that the two
// types cannot drift apart: every violation field is defined once, in
// ViolationInfo.
type ViolationRecord struct {
	ViolationInfo `json:",inline"`

	// ID is a per-policy unique identifier allocated by the controller
	// when the record is first observed. It is stable across re-scrapes
	// of the same logical violation, so consumers can refer to a single
	// record by ID (for example when correlating with external events).
	//
	// Stored as int64 (not uint64) for compatibility with the Kubernetes
	// field-management machinery used by controller-runtime's test
	// fixtures; the counter is monotonically increasing and never goes
	// negative, so the sign bit is never set in practice.
	ID int64 `json:"id"`
}

// AcknowledgedViolationRecord wraps a ViolationRecord together with the
// acknowledgement reason and timestamp.
type AcknowledgedViolationRecord struct {
	// Violation is the violation record that was acknowledged.
	Violation ViolationRecord `json:"violation"`
	// Reason is an optional field to indicate why this violation was
	// acknowledged.
	// +optional
	Reason string `json:"reason,omitempty"`
	// AcknowledgedAt is the time when the violation was acknowledged.
	// +optional
	AcknowledgedAt metav1.Time `json:"acknowledgedAt,omitempty"`
}

// clearAllowedViolations drops violations whose flow is now permitted by the
// policy template. It dispatches on the backend: the kubernetes backend keeps
// the NetworkPolicy-based structural comparison (EgressRuleEqual /
// IngressRuleEqual), while the istio backend matches against Spec.Istio.Rules.
func (wnp *WorkloadNetworkPolicy) clearAllowedViolations() {
	switch wnp.Spec.Backend {
	case PolicyBackendKubernetes:
		wnp.clearAllowedKubernetesViolations()
	case PolicyBackendIstio:
		wnp.clearAllowedIstioViolations()
	}
}

// clearAllowedKubernetesViolations drops violations whose flow matches a
// kubernetes policy template rule via exact structural comparison
// (EgressRuleEqual / IngressRuleEqual).
func (wnp *WorkloadNetworkPolicy) clearAllowedKubernetesViolations() {
	policyTemplate := wnp.Spec.Kubernetes
	wnp.Status.Violations = slices.DeleteFunc(wnp.Status.Violations, func(v ViolationRecord) bool {
		for _, rule := range policyTemplate.Ingress {
			if IngressRuleEqual(v.ToIngressRule(), rule) {
				return true
			}
		}
		for _, rule := range policyTemplate.Egress {
			if EgressRuleEqual(v.ToEgressRule(), rule) {
				return true
			}
		}
		return false
	})
}

func (wnp *WorkloadNetworkPolicy) clearAllowedIstioViolations() {
	if wnp.Spec.Istio == nil {
		return
	}

	wnp.Status.Violations = slices.DeleteFunc(wnp.Status.Violations, func(v ViolationRecord) bool {
		for _, rule := range wnp.Spec.Istio.Rules {
			if istioRuleAllowsSource(rule, v.Source) && istioRuleAllowsPort(rule, v.DstPort) {
				return true
			}
		}
		return false
	})
}

// istioRuleAllowsSource reports whether the rule allows the violation source.
// Istio principals are workload identities (SPIFFE service accounts), so the
// match is exact on the source identity: matching on the namespace alone would
// clear violations from a denied principal just because another principal in
// the same namespace is allowed. Both sides use the canonical, prefix-free
// Istio principal form (`cluster.local/ns/<ns>/sa/<sa>`, `*` for any source):
// the backend strips the `spiffe://` scheme at ingestion. When the source
// identity is unknown (e.g. it was not reported by the backend), only rules
// without a principal constraint (no `From`, no `Principals`, or `*`) can
// allow the source: we prefer keeping a violation over silently clearing one.
func istioRuleAllowsSource(rule IstioAuthorizationPolicyRule, src WorkloadRef) bool {
	if len(rule.From) == 0 {
		return true
	}
	for _, from := range rule.From {
		if len(from.Source.Principals) == 0 {
			return true
		}
		for _, principal := range from.Source.Principals {
			if principal == "*" || principal == src.Identity {
				return true
			}
		}
	}
	return false
}

func istioRuleAllowsPort(rule IstioAuthorizationPolicyRule, dstPort int32) bool {
	if len(rule.To) == 0 {
		return true
	}
	for _, to := range rule.To {
		if len(to.Operation.Ports) == 0 {
			return true
		}
		for _, port := range to.Operation.Ports {
			if istioPortMatches(port, dstPort) {
				return true
			}
		}
	}
	return false
}

func istioPortMatches(portSpec string, dstPort int32) bool {
	lo, hi, ok := parseIstioPortRange(portSpec)
	if !ok {
		return false
	}
	return dstPort >= lo && dstPort <= hi
}

func parseIstioPortRange(portSpec string) (int32, int32, bool) {
	loStr, hiStr, _ := strings.Cut(portSpec, "-")
	lo, err := strconv.ParseInt(loStr, 10, 32)
	if err != nil {
		return 0, 0, false
	}
	if hiStr == "" {
		return int32(lo), int32(lo), true
	}
	hi, err := strconv.ParseInt(hiStr, 10, 32)
	if err != nil {
		return 0, 0, false
	}
	return int32(lo), int32(hi), true
}

// ToEgressRule builds an egress rule from the violation for comparison.
func (v ViolationRecord) ToEgressRule() networkingv1.NetworkPolicyEgressRule {
	port := intstr.FromInt32(v.DstPort)
	proto := v.Protocol

	return networkingv1.NetworkPolicyEgressRule{
		To: []networkingv1.NetworkPolicyPeer{
			{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						corev1.LabelMetadataName: v.Dest.Namespace,
					},
				},
			},
		},
		Ports: []networkingv1.NetworkPolicyPort{
			{
				Protocol: &proto,
				Port:     &port,
			},
		},
	}
}

// ToIngressRule builds an ingress rule from the violation for comparison.
func (v ViolationRecord) ToIngressRule() networkingv1.NetworkPolicyIngressRule {
	port := intstr.FromInt32(v.DstPort)
	proto := v.Protocol

	return networkingv1.NetworkPolicyIngressRule{
		From: []networkingv1.NetworkPolicyPeer{
			{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						corev1.LabelMetadataName: v.Source.Namespace,
					},
				},
			},
		},
		Ports: []networkingv1.NetworkPolicyPort{
			{
				Protocol: &proto,
				Port:     &port,
			},
		},
	}
}

// mergeScrapedViolations merges scraped violations into the status with dedup.
// New records get the next monotonic ID; ViolationCount bumps for every observed record.
func (s *WorkloadNetworkPolicyStatus) mergeScrapedViolations(scraped []ViolationRecord) {
	indexByKey := make(map[ViolationRecordKey]int, len(s.Violations))
	for i, r := range s.Violations {
		indexByKey[r.Key()] = i
	}

	for _, v := range scraped {
		key := v.Key()
		if idx, ok := indexByKey[key]; ok {
			// Refresh timestamp only if newer.
			if v.Timestamp.Time.After(s.Violations[idx].Timestamp.Time) {
				s.Violations[idx].Timestamp = v.Timestamp
			}
		} else {
			v.ID = s.ViolationCount
			s.Violations = append(s.Violations, v)
			indexByKey[key] = len(s.Violations) - 1
		}
		s.ViolationCount++
	}

	// Newest-first sort.
	slices.SortStableFunc(s.Violations, func(a, b ViolationRecord) int {
		return b.Timestamp.Time.Compare(a.Timestamp.Time)
	})

	if len(s.Violations) > maxViolationRecords {
		s.Violations = s.Violations[:maxViolationRecords]
	}
}

// acknowledgeViolationsFromAnnotations processes security.kubewarden.io/acknowledge-<id>
// annotations and moves matching violations into AcknowledgedViolations.
func (wnp *WorkloadNetworkPolicy) acknowledgeViolationsFromAnnotations(now metav1.Time) []AcknowledgedViolationRecord {
	annotations := wnp.GetAnnotations()
	if len(annotations) == 0 {
		return nil
	}

	acknowledges := make(map[int64]annotationInfo, len(annotations))

	for k, reason := range annotations {
		idStr, found := strings.CutPrefix(k, ViolationAcknowledgePrefix)
		if !found {
			continue
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			continue
		}

		acknowledges[id] = annotationInfo{
			annotationKey: k,
			reason:        reason,
		}
	}

	if len(acknowledges) == 0 {
		return nil
	}

	if wnp.Status.AcknowledgedViolations == nil {
		wnp.Status.AcknowledgedViolations = make([]AcknowledgedViolationRecord, 0)
	}

	ackToReturn := make([]AcknowledgedViolationRecord, 0)

	wnp.Status.Violations = slices.DeleteFunc(wnp.Status.Violations, func(v ViolationRecord) bool {
		info, ok := acknowledges[v.ID]
		if !ok {
			return false
		}
		delete(annotations, info.annotationKey)

		newAcknowledgement := AcknowledgedViolationRecord{
			Violation:      v,
			Reason:         info.reason,
			AcknowledgedAt: now,
		}
		ackToReturn = append(ackToReturn, newAcknowledgement)
		wnp.Status.AcknowledgedViolations = append(wnp.Status.AcknowledgedViolations, newAcknowledgement)
		return true
	})

	// Newest-first sort.
	slices.SortStableFunc(wnp.Status.AcknowledgedViolations, func(a, b AcknowledgedViolationRecord) int {
		return b.AcknowledgedAt.Time.Compare(a.AcknowledgedAt.Time)
	})

	if len(wnp.Status.AcknowledgedViolations) > maxViolationRecords {
		wnp.Status.AcknowledgedViolations = wnp.Status.AcknowledgedViolations[:maxViolationRecords]
	}

	wnp.SetAnnotations(annotations)
	return ackToReturn
}

// RecomputeStatus runs merge → clear → acknowledge and sets ActiveViolationCount
// and ObservedGeneration. Returns newly-acknowledged records.
func (wnp *WorkloadNetworkPolicy) RecomputeStatus(
	scrapedViolations []ViolationRecord,
	now metav1.Time,
) []AcknowledgedViolationRecord {
	if wnp == nil {
		return nil
	}

	wnp.Status.mergeScrapedViolations(scrapedViolations)
	wnp.clearAllowedViolations()
	acknowledged := wnp.acknowledgeViolationsFromAnnotations(now)

	wnp.Status.ActiveViolationCount = int64(len(wnp.Status.Violations))
	wnp.Status.ObservedGeneration = wnp.Generation

	return acknowledged
}
