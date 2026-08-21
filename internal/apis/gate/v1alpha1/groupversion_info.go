// Package v1alpha1 contains the API types of the gate.unstable.cloud group.
//
// The group holds what an Ingress cannot express: who may pass through it
// (NetworkRole, NetworkRoleBinding — ADR 0002) and how a client without a
// browser identifies itself (AccessToken — ADR 0004). Routing itself stays on
// the standard networking.k8s.io/v1 Ingress (ADR 0001).
//
// +kubebuilder:object:generate=true
// +groupName=gate.unstable.cloud
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// GroupVersion is the group and version of every type in this package.
var GroupVersion = schema.GroupVersion{Group: "gate.unstable.cloud", Version: "v1alpha1"}

// SchemeBuilder registers this package's types with a runtime.Scheme.
var SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

// AddToScheme adds this package's types to a runtime.Scheme.
var AddToScheme = SchemeBuilder.AddToScheme

// Resource returns a GroupResource for the given resource in this group.
func Resource(resource string) schema.GroupResource {
	return GroupVersion.WithResource(resource).GroupResource()
}
