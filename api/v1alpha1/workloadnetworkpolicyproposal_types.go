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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type WorkloadNetworkPolicyProposalSpec struct {
	PolicyBackendSpec `json:",inline"`
}

type WorkloadNetworkPolicyProposalStatus struct {
	// conditions represent the current state of the proposal.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=wnpp
// +kubebuilder:metadata:annotations="helm.sh/resource-policy=keep"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

type WorkloadNetworkPolicyProposal struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec WorkloadNetworkPolicyProposalSpec `json:"spec"`

	// +optional
	Status WorkloadNetworkPolicyProposalStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

type WorkloadNetworkPolicyProposalList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`

	Items []WorkloadNetworkPolicyProposal `json:"items"`
}

func (wnpp *WorkloadNetworkPolicyProposal) NamespacedName() types.NamespacedName {
	if wnpp == nil {
		return types.NamespacedName{}
	}

	return types.NamespacedName{
		Namespace: wnpp.Namespace,
		Name:      wnpp.Name,
	}
}

func (wnpp *WorkloadNetworkPolicyProposal) SetPromotionLabel(mode WorkloadNetworkPolicyMode) {
	if wnpp == nil {
		return
	}
	if wnpp.Labels == nil {
		wnpp.SetLabels(map[string]string{})
	}
	wnpp.Labels[ProposalPromoteLabelKey] = string(mode)
}

// HasPromotionLabel reports whether the proposal has a valid promotion label and
// returns the target WorkloadNetworkPolicy mode when it does.
func (wnpp *WorkloadNetworkPolicyProposal) HasPromotionLabel() (WorkloadNetworkPolicyMode, bool) {
	if wnpp == nil {
		return "", false
	}
	val, ok := wnpp.Labels[ProposalPromoteLabelKey]
	if !ok {
		return "", false
	}
	switch WorkloadNetworkPolicyMode(val) {
	case WorkloadNetworkPolicyModeMonitor:
		return WorkloadNetworkPolicyModeMonitor, true
	case WorkloadNetworkPolicyModeProtect:
		return WorkloadNetworkPolicyModeProtect, true
	default:
		return "", false
	}
}
