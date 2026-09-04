/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"errors"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// WorkloadNetworkPolicyMode selects how a WorkloadNetworkPolicy is interpreted
// at runtime.
// +kubebuilder:validation:Enum=monitor;protect
type WorkloadNetworkPolicyMode string

const (
	// WorkloadNetworkPolicyModeMonitor records observed traffic against the
	// policy without enforcing it (dry-run).
	WorkloadNetworkPolicyModeMonitor WorkloadNetworkPolicyMode = "monitor"

	// WorkloadNetworkPolicyModeProtect enforces the policy on the cluster.
	WorkloadNetworkPolicyModeProtect WorkloadNetworkPolicyMode = "protect"
)

// WorkloadNetworkPolicySpec defines the desired state of a WorkloadNetworkPolicy.
type WorkloadNetworkPolicySpec struct {
	PolicyBackendSpec `json:",inline"`

	// Mode controls whether the policy is observed (monitor) or actively
	// enforced (protect). Defaults to monitor.
	// +kubebuilder:default=monitor
	// +optional
	Mode WorkloadNetworkPolicyMode `json:"mode,omitempty"`
}

// WorkloadNetworkPolicyStatus defines the observed state of a
// WorkloadNetworkPolicy.
type WorkloadNetworkPolicyStatus struct {
	// ObservedGeneration is the most recent generation observed for this
	// WorkloadNetworkPolicy. It corresponds to the resource's
	// metadata.generation, which is updated by the API server when the
	// spec changes.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// ViolationCount is the total number of violation records ever
	// observed for this policy, including those that have already been
	// trimmed out of Violations or cleared because the flow is now
	// permitted by the policy template. It is not guaranteed to be strongly
	// consistent and may be temporarily outdated.
	// +kubebuilder:default=0
	// +optional
	ViolationCount int64 `json:"violationCount"`
	// ActiveViolationCount is the number of currently active (non-cleared)
	// violation records. It is always equal to len(Violations) and is
	// updated in the same status write.
	// +kubebuilder:default=0
	// +optional
	ActiveViolationCount int64 `json:"activeViolationCount"`
	// Violations is the list of the most recent violation records
	// (max maxViolationRecords). Oldest entries are dropped when the
	// limit is reached.
	// +optional
	Violations []ViolationRecord `json:"violations,omitempty"`
	// AcknowledgedViolations is the list of the most recent violation
	// records that have been acknowledged by users (max maxViolationRecords).
	// Oldest entries are dropped when the limit is reached.
	// +optional
	AcknowledgedViolations []AcknowledgedViolationRecord `json:"acknowledgedViolations,omitempty"`
}

// WorkloadNetworkPolicy is the schema for the runtime network policy API.
// Spec carries a backend-specific policy payload (Kubernetes or Istio) and a
// mode (monitor or protect). The resource is intentionally namespaced and uses
// the `security.kubewarden.io` group to avoid colliding with the upstream
// `networking.k8s.io/NetworkPolicy` kind.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wnp
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Active Violations",type=integer,JSONPath=`.status.activeViolationCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type WorkloadNetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec WorkloadNetworkPolicySpec `json:"spec"`
	// +optional
	Status WorkloadNetworkPolicyStatus `json:"status,omitempty"`
}

// WorkloadNetworkPolicyList is a list of WorkloadNetworkPolicy.
// +kubebuilder:object:root=true
type WorkloadNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`

	Items []WorkloadNetworkPolicy `json:"items"`
}

func (wnp *WorkloadNetworkPolicy) NamespacedName() types.NamespacedName {
	if wnp == nil {
		return types.NamespacedName{}
	}

	return types.NamespacedName{
		Namespace: wnp.Namespace,
		Name:      wnp.Name,
	}
}

func (wnp *WorkloadNetworkPolicy) SetPromotedLabel(proposalName string) error {
	if wnp == nil {
		return errors.New("WorkloadNetworkPolicy is nil")
	}

	// k8s labels must have 63 chars or less.
	// We catch here the error instead of letting the API server handle it.
	const maxLabelValueLength = 63
	if len(proposalName) > maxLabelValueLength {
		return fmt.Errorf("proposalName %q is too long", proposalName)
	}

	if wnp.Labels == nil {
		wnp.SetLabels(map[string]string{})
	}

	wnp.Labels[PolicyPromotedFromLabelKey] = proposalName
	return nil
}

func (wnp *WorkloadNetworkPolicy) HasPromotedLabel(proposalName string) bool {
	if wnp == nil {
		return false
	}
	return wnp.Labels[PolicyPromotedFromLabelKey] == proposalName
}

func (wnp *WorkloadNetworkPolicySpec) GetSelector() (metav1.LabelSelector, error) {
	if wnp == nil {
		return metav1.LabelSelector{}, errors.New("WorkloadNetworkPolicy is nil")
	}

	switch wnp.Backend {
	case PolicyBackendKubernetes:
		if wnp.Kubernetes == nil {
			return metav1.LabelSelector{}, errors.New("WorkloadNetworkPolicy kubernetes backend is nil")
		}
		return wnp.Kubernetes.PodSelector, nil
	case PolicyBackendIstio:
		if wnp.Istio == nil {
			return metav1.LabelSelector{}, errors.New("WorkloadNetworkPolicy istio backend is nil")
		}
		return wnp.Istio.Selector, nil
	default:
		return metav1.LabelSelector{}, fmt.Errorf("unsupported WorkloadNetworkPolicy backend: %s", wnp.Backend)
	}
}
