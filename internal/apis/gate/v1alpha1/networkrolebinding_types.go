package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RoleReference names the NetworkRole a binding grants.
//
// The reference is namespace-local. A role and the binding that grants it
// belong to the same namespace as the resource they protect, so a binding can
// never reach across a namespace boundary to open something up.
type RoleReference struct {
	// name of the NetworkRole in the same namespace as this binding.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	Name string `json:"name"`
}

// Subject is a principal a role is granted to.
type Subject struct {
	// kind of principal. Only User exists today.
	//
	// +kubebuilder:default=User
	// +optional
	Kind SubjectKind `json:"kind,omitempty"`

	// name of the principal: github:<login>, google:<mail address>,
	// system:authenticated or system:unauthenticated.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^(github:[A-Za-z0-9][A-Za-z0-9-]{0,38}|google:[^@\s]+@[^@\s]+\.[^@\s]+|system:(authenticated|unauthenticated))$`
	Name string `json:"name"`
}

// NetworkRoleBindingSpec grants a role to a set of subjects.
type NetworkRoleBindingSpec struct {
	// roleRef names the NetworkRole being granted.
	//
	// +kubebuilder:validation:Required
	RoleRef RoleReference `json:"roleRef"`

	// subjects the role is granted to.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=128
	// +listType=atomic
	Subjects []Subject `json:"subjects"`
}

// ConditionRoleResolved reports whether spec.roleRef was found.
const ConditionRoleResolved = "RoleResolved"

// NetworkRoleBindingStatus reports whether the binding currently grants
// anything.
type NetworkRoleBindingStatus struct {
	// observedGeneration is the generation of the spec this status was
	// computed from.
	//
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions of the binding. RoleResolved is set to False when
	// spec.roleRef names a NetworkRole that does not exist.
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// NetworkRoleBinding grants a NetworkRole to subjects.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=gated,shortName=netrolebinding
// +kubebuilder:printcolumn:name="Role",type=string,JSONPath=`.spec.roleRef.name`
// +kubebuilder:printcolumn:name="Resolved",type=string,JSONPath=`.status.conditions[?(@.type=="RoleResolved")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type NetworkRoleBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec NetworkRoleBindingSpec `json:"spec"`

	// +optional
	Status NetworkRoleBindingStatus `json:"status,omitempty"`
}

// NetworkRoleBindingList is a list of NetworkRoleBinding.
//
// +kubebuilder:object:root=true
type NetworkRoleBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkRoleBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkRoleBinding{}, &NetworkRoleBindingList{})
}
