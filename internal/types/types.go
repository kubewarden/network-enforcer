package types

import (
	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

type Provider string

const (
	ProviderIstio  Provider = "istio"
	ProviderCilium Provider = "cilium"
	ProviderCalico Provider = "calico"
)

// LearningEvent represents a learning event in the network enforcer.
type LearningEvent struct {
	Source   *securityv1alpha1.WorkloadRef  `json:"source"`
	Dest     *securityv1alpha1.WorkloadRef  `json:"dest"`
	DstPort  int32                          `json:"dst_port"`
	Protocol corev1.Protocol                `json:"protocol"` // "TCP", "UDP"
	Backend  securityv1alpha1.PolicyBackend `json:"backend"`
}
