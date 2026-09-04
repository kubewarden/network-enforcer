// Package violation holds the in-flight, provider-neutral representation of a
// network policy violation before it is correlated to a WorkloadNetworkPolicy.
//
// The types in this package are internal: they are never persisted on the CRD.
// The persisted form is securityv1alpha1.ViolationRecord inside
// wnp.Status.Violations; the backend of the owning policy is read from
// wnp.Spec.Backend rather than duplicated here.
package violation

import (
	networkingv1 "k8s.io/api/networking/v1"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

// Observation is the common in-flight representation produced by the backend
// scrapers (Istio, Cilium, Calico) and consumed by the shared
// violation buffer. Each scraper converts its provider-specific event (OTLP
// log for Istio, gRPC flow for Cilium/Calico) into this format, reusing the
// fields of the persisted ViolationRecord (via the embedded ViolationInfo)
// instead of introducing provider-shaped parallel types.
//
// When the controller picks an observation it creates the ViolationRecord by
// adding the ID and attaching it to the policy written in the observation
// (DenyingPolicyNamespace / DenyingPolicyName). The provider-specific workload
// identity lives in the WorkloadRef (Source.Identity / Dest.Identity): SPIFFE
// for Istio, numeric security ID for Cilium, empty for Calico.
type Observation struct {
	// ViolationInfo is the violation without the controller-assigned ID.
	// Action is set by the producer (the istio watcher knows whether the
	// event is a monitor dry-run or a protect enforcement).
	securityv1alpha1.ViolationInfo

	// Provider is the backend that observed the violation. It is carried only
	// in-flight: an observation may match no policy (the key security signal)
	// and at that point there is no policy to inherit a backend from. It is
	// emitted to OTel and never stored.
	Provider securityv1alpha1.PolicyBackend

	// Direction is necessary to understand if the violation happened at
	// the source (egress) or destination (ingress)
	Direction networkingv1.PolicyType
}
