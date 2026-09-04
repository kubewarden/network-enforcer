package controller

import (
	"fmt"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

func getProposalName(wk *securityv1alpha1.WorkloadRef, direction networkingv1.PolicyType) string {
	return fmt.Sprintf(
		"%s-%s-%s",
		strings.ToLower(string(wk.OwnerKind)),
		wk.OwnerName,
		strings.ToLower(string(direction)),
	)
}

func getProposalMetadata(
	wk *securityv1alpha1.WorkloadRef,
	direction networkingv1.PolicyType,
) *securityv1alpha1.WorkloadNetworkPolicyProposal {
	return &securityv1alpha1.WorkloadNetworkPolicyProposal{
		Name:      getProposalName(wk, direction),
		Namespace: wk.Namespace,
	}
}
