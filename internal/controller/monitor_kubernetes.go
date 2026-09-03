package controller

import (
	"fmt"
	"time"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/violation"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (r *LearningReconciler) evaluateMonitorViolation(
	policy securityv1alpha1.WorkloadNetworkPolicy,
	workload *securityv1alpha1.WorkloadRef,
	peer *securityv1alpha1.WorkloadRef,
	protocol corev1.Protocol,
	direction networkingv1.PolicyType,
	dstPort int32,
) error {
	policyPeer, policyPort := buildPeerAndPort(peer, protocol, dstPort)
	spec := policy.Spec.Kubernetes
	switch direction {
	case networkingv1.PolicyTypeEgress:
		if !containsPeerPort(spec.Egress, policyPeer, policyPort) {
			return r.sendMonitorViolation(policy.Name, workload, peer, protocol, direction, dstPort)
		}
	case networkingv1.PolicyTypeIngress:
		if !containsPeerPort(spec.Ingress, policyPeer, policyPort) {
			return r.sendMonitorViolation(policy.Name, workload, peer, protocol, direction, dstPort)
		}
	default:
		return fmt.Errorf("unknown policy direction %q", direction)
	}
	return nil
}

type peerPortRule interface {
	networkingv1.NetworkPolicyEgressRule | networkingv1.NetworkPolicyIngressRule
}

func containsPeerPort[T peerPortRule](
	rules []T,
	peer networkingv1.NetworkPolicyPeer,
	port networkingv1.NetworkPolicyPort,
) bool {
	peerAndPorts := func(rule T) ([]networkingv1.NetworkPolicyPeer, []networkingv1.NetworkPolicyPort) {
		switch r := any(rule).(type) {
		case networkingv1.NetworkPolicyEgressRule:
			return r.To, r.Ports
		case networkingv1.NetworkPolicyIngressRule:
			return r.From, r.Ports
		default:
			return nil, nil
		}
	}

	for _, rule := range rules {
		rulePeers, rulePorts := peerAndPorts(rule)
		if len(rulePeers) != 1 || !securityv1alpha1.PolicyPeerEqual(rulePeers[0], peer) {
			continue
		}
		for _, existingPort := range rulePorts {
			if securityv1alpha1.PolicyPortEqual(existingPort, port) {
				return true
			}
		}
	}

	return false
}

func (r *LearningReconciler) sendMonitorViolation(
	policyName string,
	workload *securityv1alpha1.WorkloadRef,
	peer *securityv1alpha1.WorkloadRef,
	protocol corev1.Protocol,
	direction networkingv1.PolicyType,
	dstPort int32,
) error {
	obs := generateViolationObservation(policyName, workload, peer, protocol, direction, dstPort)
	if r.violationBuffer.Record(obs) {
		return fmt.Errorf("violation buffer full, dropping violation observation: %v", obs)
	}
	return nil
}

func generateViolationObservation(
	policyName string,
	workload *securityv1alpha1.WorkloadRef,
	peer *securityv1alpha1.WorkloadRef,
	protocol corev1.Protocol,
	direction networkingv1.PolicyType,
	dstPort int32,
) violation.Observation {
	source := *workload
	dest := *peer
	if direction == networkingv1.PolicyTypeIngress {
		source, dest = *peer, *workload
	}

	observation := violation.Observation{
		Timestamp:              metav1.NewTime(time.Now()),
		Source:                 source,
		Dest:                   dest,
		Protocol:               protocol,
		DstPort:                dstPort,
		Action:                 securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
		DenyingPolicyNamespace: workload.Namespace,
		DenyingPolicyName:      policyName,
		Provider:               securityv1alpha1.PolicyBackendKubernetes,
	}
	return observation
}
