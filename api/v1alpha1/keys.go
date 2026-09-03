package v1alpha1

const (
	// ProposalPromoteLabelKey is set on a WorkloadNetworkPolicyProposal when it
	// is promoted to a WorkloadNetworkPolicy.
	// Valid values are WorkloadNetworkPolicyMode strings ("monitor", "protect").
	ProposalPromoteLabelKey = "security.kubewarden.io/promote"

	// PolicyPromotedFromLabelKey is set on a WorkloadNetworkPolicy when it is
	// created by promoting a WorkloadNetworkPolicyProposal.
	PolicyPromotedFromLabelKey = "security.kubewarden.io/promoted-from"

	// ViolationAcknowledgePrefix is the prefix of annotation key used to acknowledge a violation.
	// An annotation of the form security.kubewarden.io/acknowledge-<id>: "<reason>" moves the
	// violation record with that ID into AcknowledgedViolations.
	ViolationAcknowledgePrefix = "security.kubewarden.io/acknowledge-"
)
