package ingress_test

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

// corev1TypedRef is a backend gated cannot forward to: a reference to an
// arbitrary object rather than a Service.
var corev1TypedRef = corev1.TypedLocalObjectReference{
	APIGroup: ptr.To("example.com"),
	Kind:     "StorageBucket",
	Name:     "assets",
}
