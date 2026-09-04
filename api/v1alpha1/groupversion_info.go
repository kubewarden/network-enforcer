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

// Package v1alpha1 contains API Schema definitions for the security v1alpha1 API group.
// +kubebuilder:object:generate=true
// +groupName=security.kubewarden.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	//nolint:gochecknoglobals // Kubebuilder API registration requires package-level variables
	GroupVersion = schema.GroupVersion{Group: "security.kubewarden.io", Version: "v1alpha1"}
	//nolint:gochecknoglobals // Kubebuilder API registration requires package-level variables
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	//nolint:gochecknoglobals // Kubebuilder API registration requires package-level variables
	AddToScheme = SchemeBuilder.AddToScheme
)

// addKnownTypes registers the API types belonging to this group version with the scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(
		GroupVersion,
		&WorkloadNetworkPolicy{},
		&WorkloadNetworkPolicyList{},
		&WorkloadNetworkPolicyProposal{},
		&WorkloadNetworkPolicyProposalList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
