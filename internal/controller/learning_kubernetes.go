package controller

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/types"
)

func (r *LearningReconciler) processKubernetesLearningEvent(ctx context.Context, req types.LearningEvent) error {
	if req.Source == nil || req.Dest == nil {
		return errors.New("invalid learning event: missing source or destination")
	}
	// For each learning event we maintain two separate proposals:
	// - source workload -> egress rule
	// - destination workload -> ingress rule
	if err := r.reconcileKubernetesProposal(
		ctx,
		req.Source,
		req.Dest,
		networkingv1.PolicyTypeEgress,
		req.Protocol,
		req.DstPort,
	); err != nil {
		return fmt.Errorf("reconcile egress proposal: %w", err)
	}

	if err := r.reconcileKubernetesProposal(
		ctx,
		req.Dest,
		req.Source,
		networkingv1.PolicyTypeIngress,
		req.Protocol,
		req.DstPort,
	); err != nil {
		return fmt.Errorf("reconcile ingress proposal: %w", err)
	}

	return nil
}

func (r *LearningReconciler) reconcileKubernetesProposal(
	ctx context.Context,
	workload *securityv1alpha1.WorkloadRef,
	peer *securityv1alpha1.WorkloadRef,
	direction networkingv1.PolicyType,
	protocol corev1.Protocol,
	dstPort int32,
) error {
	proposal := getProposalMetadata(workload, direction)

	policies, err := checkExistingPolicy(ctx, r.Client, workload.Namespace, proposal.Name)
	if err != nil {
		return fmt.Errorf("checking existing policies for %s/%s: %w", workload.Namespace, proposal.Name, err)
	}
	switch len(policies) {
	case 0:
		// Continue and maintain the proposal.
	case 1:
		// Policy already promoted; skip learning updates for this proposal.
		policy := policies[0]
		if policy.Spec.Mode == securityv1alpha1.WorkloadNetworkPolicyModeProtect {
			// we do nothing, the violation are reported by the cni
			return nil
		}
		if err = r.evaluateMonitorViolation(policy, workload, peer, protocol, direction, dstPort); err != nil {
			log.FromContext(ctx).Info("Failed to evaluate monitor violation", "msg", err.Error())
		}
		return nil
	default:
		return errors.New("multiple policies associated with the same proposal")
	}

	if _, err = controllerutil.CreateOrUpdate(ctx, r.Client, proposal, func() error {
		proposal.Spec.Backend = securityv1alpha1.PolicyBackendKubernetes
		if proposal.Spec.Kubernetes == nil {
			proposal.Spec.Kubernetes = &networkingv1.NetworkPolicySpec{}
		}

		spec := proposal.Spec.Kubernetes
		if len(spec.PolicyTypes) == 0 {
			spec.PodSelector = workload.Selector
			spec.PolicyTypes = []networkingv1.PolicyType{direction}
		}

		policyPeer, policyPort := buildPeerAndPort(peer, protocol, dstPort)
		switch direction {
		case networkingv1.PolicyTypeEgress:
			spec.Egress = upsertEgressRuleByPeer(spec.Egress, policyPeer, policyPort)
		case networkingv1.PolicyTypeIngress:
			spec.Ingress = upsertIngressRuleByPeer(spec.Ingress, policyPeer, policyPort)
		default:
			return fmt.Errorf("unknown policy direction %q", direction)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("create or update proposal %s/%s: %w", proposal.Namespace, proposal.Name, err)
	}

	if err = r.setOwnerReference(ctx, proposal, workload); err != nil {
		return fmt.Errorf("setting owner reference on proposal %s/%s: %w", proposal.Namespace, proposal.Name, err)
	}

	return nil
}

func buildPeerAndPort(
	peer *securityv1alpha1.WorkloadRef,
	protocol corev1.Protocol,
	dstPort int32,
) (networkingv1.NetworkPolicyPeer, networkingv1.NetworkPolicyPort) {
	port := intstr.FromInt32(dstPort)

	policyPeer := networkingv1.NetworkPolicyPeer{
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{corev1.LabelMetadataName: peer.Namespace},
		},
		PodSelector: &peer.Selector,
	}

	policyPort := networkingv1.NetworkPolicyPort{
		Protocol: &protocol,
		Port:     &port,
	}

	return policyPeer, policyPort
}

func upsertEgressRuleByPeer(
	rules []networkingv1.NetworkPolicyEgressRule,
	peer networkingv1.NetworkPolicyPeer,
	port networkingv1.NetworkPolicyPort,
) []networkingv1.NetworkPolicyEgressRule {
	for i := range rules {
		// Right now the peer is always one for each rule, if something should change
		// we should update this logic.
		if len(rules[i].To) == 1 && securityv1alpha1.PolicyPeerEqual(rules[i].To[0], peer) {
			for _, existingPort := range rules[i].Ports {
				if securityv1alpha1.PolicyPortEqual(existingPort, port) {
					return rules
				}
			}
			rules[i].Ports = append(rules[i].Ports, port)
			return rules
		}
	}

	return append(rules, networkingv1.NetworkPolicyEgressRule{
		To:    []networkingv1.NetworkPolicyPeer{peer},
		Ports: []networkingv1.NetworkPolicyPort{port},
	})
}

func upsertIngressRuleByPeer(
	rules []networkingv1.NetworkPolicyIngressRule,
	peer networkingv1.NetworkPolicyPeer,
	port networkingv1.NetworkPolicyPort,
) []networkingv1.NetworkPolicyIngressRule {
	for i := range rules {
		if len(rules[i].From) == 1 && securityv1alpha1.PolicyPeerEqual(rules[i].From[0], peer) {
			for _, existingPort := range rules[i].Ports {
				if securityv1alpha1.PolicyPortEqual(existingPort, port) {
					return rules
				}
			}
			rules[i].Ports = append(rules[i].Ports, port)
			return rules
		}
	}

	return append(rules, networkingv1.NetworkPolicyIngressRule{
		From:  []networkingv1.NetworkPolicyPeer{peer},
		Ports: []networkingv1.NetworkPolicyPort{port},
	})
}
