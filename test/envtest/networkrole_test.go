//go:build envtest

package envtest_test

import (
	"context"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const minimalNetworkRole = `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRole
metadata:
  name: minimal
spec:
  targetRef:
    name: example
  rules:
    - paths: ["/"]
      methods: ["GET"]
`

func TestNetworkRoleDefaults(t *testing.T) {
	ns := newNamespace(t)
	got := mustCreate(t, ns, minimalNetworkRole)

	// A targetRef that names only a resource must mean the Ingress of that
	// name, so that the common case stays short.
	if v := field(t, got, "spec", "targetRef", "group"); v != "networking.k8s.io" {
		t.Errorf("spec.targetRef.group = %q, want %q", v, "networking.k8s.io")
	}
	if v := field(t, got, "spec", "targetRef", "kind"); v != "Ingress" {
		t.Errorf("spec.targetRef.kind = %q, want %q", v, "Ingress")
	}

	// The namespace is deliberately left unset rather than defaulted to the
	// role's own namespace: the controller applies that fallback, and
	// writing it into the object would freeze it there.
	if _, found, _ := unstructured.NestedString(got.Object, "spec", "targetRef", "namespace"); found {
		t.Error("spec.targetRef.namespace was defaulted, want it left unset")
	}
}

func TestNetworkRoleRejectsInvalidSpecs(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
	}{
		{
			name: "targetRef without a name",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRole
metadata:
  name: no-target-name
spec:
  targetRef:
    kind: Ingress
  rules:
    - paths: ["/"]
      methods: ["GET"]
`,
		},
		{
			name: "no targetRef at all",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRole
metadata:
  name: no-target
spec:
  rules:
    - paths: ["/"]
      methods: ["GET"]
`,
		},
		{
			name: "no spec at all",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRole
metadata:
  name: no-spec
`,
		},
		{
			// A kind gated cannot resolve would leave the target
			// unprotected without saying so, which is exactly the
			// silent hole fail-open makes possible.
			name: "a kind that is not supported yet",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRole
metadata:
  name: httproute-target
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: example
  rules:
    - paths: ["/"]
      methods: ["GET"]
`,
		},
		{
			name: "a lower-case method",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRole
metadata:
  name: lowercase-method
spec:
  targetRef:
    name: example
  rules:
    - paths: ["/"]
      methods: ["get"]
`,
		},
		{
			name: "a method that is not an HTTP method",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRole
metadata:
  name: unknown-method
spec:
  targetRef:
    name: example
  rules:
    - paths: ["/"]
      methods: ["READ"]
`,
		},
		{
			name: "a path without a leading slash",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRole
metadata:
  name: relative-path
spec:
  targetRef:
    name: example
  rules:
    - paths: ["api"]
      methods: ["GET"]
`,
		},
		{
			name: "a wildcard in the middle of a path",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRole
metadata:
  name: infix-wildcard
spec:
  targetRef:
    name: example
  rules:
    - paths: ["/api/*/v1"]
      methods: ["GET"]
`,
		},
		{
			name: "a rule with no paths",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRole
metadata:
  name: no-paths
spec:
  targetRef:
    name: example
  rules:
    - paths: []
      methods: ["GET"]
`,
		},
		{
			name: "a rule with no methods",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRole
metadata:
  name: no-methods
spec:
  targetRef:
    name: example
  rules:
    - paths: ["/"]
      methods: []
`,
		},
	}

	ns := newNamespace(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := create(t, ns, tt.manifest)
			assertRejected(t, err)
		})
	}
}

func TestNetworkRoleAcceptsTheFullPathVocabulary(t *testing.T) {
	ns := newNamespace(t)

	// The vocabulary is RBAC's nonResourceURLs: exact, prefix via a
	// trailing star, and a bare star for everything.
	mustCreate(t, ns, `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRole
metadata:
  name: full-vocabulary
spec:
  targetRef:
    namespace: other
    name: example
  rules:
    - paths: ["/", "/healthz", "/api/*", "*"]
      methods: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "CONNECT", "OPTIONS", "TRACE"]
    - paths: ["*"]
      methods: ["*"]
`)
}

func TestNetworkRoleStatusIsASubresource(t *testing.T) {
	ns := newNamespace(t)
	obj := mustCreate(t, ns, minimalNetworkRole)

	// Writing the status through the main resource must be ignored, so that
	// a controller reconciling the spec cannot clobber the status and the
	// other way round.
	if err := unstructured.SetNestedField(obj.Object, int64(99), "status", "observedGeneration"); err != nil {
		t.Fatalf("setting status.observedGeneration: %v", err)
	}
	if err := k8sClient.Update(context.Background(), obj); err != nil {
		t.Fatalf("Update() = %v, want nil", err)
	}
	if _, found, _ := unstructured.NestedInt64(obj.Object, "status", "observedGeneration"); found {
		t.Error("status survived an update of the main resource, want it dropped")
	}

	// The status subresource, on the other hand, must accept it.
	if err := unstructured.SetNestedField(obj.Object, int64(1), "status", "observedGeneration"); err != nil {
		t.Fatalf("setting status.observedGeneration: %v", err)
	}
	if err := unstructured.SetNestedSlice(obj.Object, []any{
		map[string]any{
			"namespace": ns,
			"name":      "example",
			"hosts":     []any{"app.example.com"},
		},
	}, "status", "resolvedTargets"); err != nil {
		t.Fatalf("setting status.resolvedTargets: %v", err)
	}
	if err := k8sClient.Status().Update(context.Background(), obj); err != nil {
		t.Fatalf("Status().Update() = %v, want nil", err)
	}

	reread := object(t, ns, minimalNetworkRole)
	if err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(obj), reread); err != nil {
		t.Fatalf("Get() = %v, want nil", err)
	}
	targets, found, err := unstructured.NestedSlice(reread.Object, "status", "resolvedTargets")
	if err != nil || !found {
		t.Fatalf("status.resolvedTargets: found=%v err=%v, want it persisted", found, err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(status.resolvedTargets) = %d, want 1", len(targets))
	}
	if name := targets[0].(map[string]any)["name"]; name != "example" {
		t.Errorf("status.resolvedTargets[0].name = %v, want %q", name, "example")
	}
}

// assertRejected fails unless the API server turned the manifest away for a
// reason the schema is responsible for.
func assertRejected(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		t.Fatal("Create() = nil, want the API server to reject the manifest")
	}
	if !apierrors.IsInvalid(err) && !apierrors.IsBadRequest(err) {
		t.Fatalf("Create() = %v, want an Invalid or BadRequest error", err)
	}
}
