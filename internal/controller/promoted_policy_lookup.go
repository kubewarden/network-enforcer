package controller

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

func hasPromotedPolicy(
	ctx context.Context,
	c client.Client,
	namespace string,
	proposalName string,
) (bool, error) {
	policies, err := checkExistingPolicy(ctx, c, namespace, proposalName)
	if err != nil {
		return false, err
	}
	return len(policies) > 0, nil
}

func checkExistingPolicy(
	ctx context.Context,
	c client.Client,
	namespace string,
	proposalName string,
) ([]securityv1alpha1.WorkloadNetworkPolicy, error) {
	var policies securityv1alpha1.WorkloadNetworkPolicyList
	matchingLabels := client.MatchingLabels{
		securityv1alpha1.PolicyPromotedFromLabelKey: proposalName,
	}
	if err := c.List(
		ctx,
		&policies,
		client.InNamespace(namespace),
		matchingLabels,
	); err != nil {
		return nil, err
	}

	return policies.Items, nil
}
