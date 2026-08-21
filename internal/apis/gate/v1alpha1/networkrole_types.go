package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TargetGroupNetworking is the API group of the only kind that can be
// protected today.
const TargetGroupNetworking = "networking.k8s.io"

// TargetKindIngress is the only kind that can be protected today. ADR 0001
// keeps the door open for HTTPRoute: adding it means widening the enum on
// TargetReference, not reshaping the reference.
const TargetKindIngress = "Ingress"

// TargetReference names the resource a NetworkRole protects.
//
// The target is named, not described by hostname: a hostname written here
// would keep pointing at nothing after the Ingress changed hosts, and a
// NetworkRole that resolves to nothing leaves the Ingress wide open
// (ADR 0002 chooses fail-open).
type TargetReference struct {
	// group is the API group of the target. Only the Ingress group is
	// supported today.
	//
	// +kubebuilder:validation:Enum=networking.k8s.io
	// +kubebuilder:default=networking.k8s.io
	// +optional
	Group string `json:"group,omitempty"`

	// kind is the kind of the target. Only Ingress is supported today.
	//
	// +kubebuilder:validation:Enum=Ingress
	// +kubebuilder:default=Ingress
	// +optional
	Kind string `json:"kind,omitempty"`

	// namespace of the target. Defaults to the namespace of the NetworkRole
	// itself.
	//
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// name of the target.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	Name string `json:"name"`
}

// HTTPMethod is an upper-case HTTP method name, or "*" for every method.
//
// +kubebuilder:validation:Enum="*";GET;HEAD;POST;PUT;PATCH;DELETE;CONNECT;OPTIONS;TRACE
type HTTPMethod string

// MethodAll matches every HTTP method.
const MethodAll HTTPMethod = "*"

// NetworkRoleRule is one grant: a set of paths and the methods allowed on
// them. Rules never deny; a request is allowed when any rule of any role bound
// to the subject allows it (ADR 0002), so evaluation never depends on order.
type NetworkRoleRule struct {
	// paths this rule covers, in the vocabulary of RBAC nonResourceURLs:
	// an exact path, a path ending in "*" for a prefix match, or "*" alone
	// for every path.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=1024
	// +kubebuilder:validation:items:Pattern=`^(\*|/[^*]*\*?)$`
	// +listType=atomic
	Paths []string `json:"paths"`

	// methods allowed on those paths.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	Methods []HTTPMethod `json:"methods"`
}

// NetworkRoleSpec declares what a role permits.
type NetworkRoleSpec struct {
	// targetRef names the resource this role protects.
	//
	// +kubebuilder:validation:Required
	TargetRef TargetReference `json:"targetRef"`

	// rules are the grants this role carries. An empty list grants nothing,
	// which still marks the target as protected.
	//
	// +kubebuilder:validation:MaxItems=128
	// +listType=atomic
	// +optional
	Rules []NetworkRoleRule `json:"rules,omitempty"`
}

// ResolvedTarget is a target that was found, along with the hostnames it
// serves. Recording the hosts here is what makes a fail-open hole visible: a
// role whose target never resolves shows up as an empty list and a false
// TargetResolved condition instead of silently protecting nothing.
type ResolvedTarget struct {
	// namespace of the resolved target.
	Namespace string `json:"namespace"`

	// name of the resolved target.
	Name string `json:"name"`

	// hosts the resolved target serves.
	//
	// +listType=atomic
	// +optional
	Hosts []string `json:"hosts,omitempty"`
}

// ConditionTargetResolved reports whether spec.targetRef was found.
const ConditionTargetResolved = "TargetResolved"

// NetworkRoleStatus reports what the role currently resolves to.
type NetworkRoleStatus struct {
	// observedGeneration is the generation of the spec this status was
	// computed from.
	//
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// resolvedTargets are the targets spec.targetRef was resolved to.
	//
	// +listType=atomic
	// +optional
	ResolvedTargets []ResolvedTarget `json:"resolvedTargets,omitempty"`

	// conditions of the role. TargetResolved is set to False when
	// spec.targetRef names something that does not exist.
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// NetworkRole declares what may be done to a protected resource.
//
// A resource that no NetworkRole names is not protected at all: it is served
// without authentication (ADR 0002).
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=gated,shortName=netrole
// +kubebuilder:printcolumn:name="Target",type=string,JSONPath=`.spec.targetRef.name`
// +kubebuilder:printcolumn:name="Resolved",type=string,JSONPath=`.status.conditions[?(@.type=="TargetResolved")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type NetworkRole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec NetworkRoleSpec `json:"spec"`

	// +optional
	Status NetworkRoleStatus `json:"status,omitempty"`
}

// NetworkRoleList is a list of NetworkRole.
//
// +kubebuilder:object:root=true
type NetworkRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkRole `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkRole{}, &NetworkRoleList{})
}
