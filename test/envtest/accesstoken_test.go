//go:build envtest

package envtest_test

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const minimalAccessToken = `
apiVersion: gate.unstable.cloud/v1alpha1
kind: AccessToken
metadata:
  name: registry
spec:
  subject: github:octocat
`

func TestAccessTokenMinimalSpec(t *testing.T) {
	ns := newNamespace(t)
	got := mustCreate(t, ns, minimalAccessToken)

	if v := field(t, got, "spec", "subject"); v != "github:octocat" {
		t.Errorf("spec.subject = %q, want %q", v, "github:octocat")
	}

	// secretName stays unset so the controller can fall back to the
	// AccessToken's own name; defaulting it here would freeze the choice.
	if _, found, _ := unstructured.NestedString(got.Object, "spec", "secretName"); found {
		t.Error("spec.secretName was defaulted, want it left unset")
	}
}

func TestAccessTokenRejectsInvalidSpecs(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
	}{
		{
			name: "no subject",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: AccessToken
metadata:
  name: no-subject
spec: {}
`,
		},
		{
			name: "no spec at all",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: AccessToken
metadata:
  name: no-spec
`,
		},
		{
			// A token has to belong to someone. Acting as "anyone"
			// would hand every holder whatever the anonymous rules
			// already grant, which needs no token.
			name: "an authenticated system subject",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: AccessToken
metadata:
  name: system-authenticated
spec:
  subject: system:authenticated
`,
		},
		{
			name: "an unauthenticated system subject",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: AccessToken
metadata:
  name: system-unauthenticated
spec:
  subject: system:unauthenticated
`,
		},
		{
			name: "a subject without a provider prefix",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: AccessToken
metadata:
  name: bare-subject
spec:
  subject: octocat
`,
		},
		{
			name: "a secretName that is not a resource name",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: AccessToken
metadata:
  name: bad-secret-name
spec:
  subject: github:octocat
  secretName: Registry_Token
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

func TestAccessTokenStatusHoldsOnlyTheHash(t *testing.T) {
	ns := newNamespace(t)
	obj := mustCreate(t, ns, minimalAccessToken)

	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	setStatus(t, obj, map[string]any{
		"observedGeneration": int64(1),
		"secretRef":          map[string]any{"name": "registry"},
		"tokenHash":          hash,
		"lastUsedTime":       "2026-08-21T00:00:00Z",
	})
	if err := k8sClient.Status().Update(context.Background(), obj); err != nil {
		t.Fatalf("Status().Update() = %v, want nil", err)
	}

	reread := object(t, ns, minimalAccessToken)
	if err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(obj), reread); err != nil {
		t.Fatalf("Get() = %v, want nil", err)
	}
	if v := field(t, reread, "status", "tokenHash"); v != hash {
		t.Errorf("status.tokenHash = %q, want %q", v, hash)
	}
	if v := field(t, reread, "status", "secretRef", "name"); v != "registry" {
		t.Errorf("status.secretRef.name = %q, want %q", v, "registry")
	}

	// The proxy matches presented tokens against this hash, so a value that
	// is not a SHA-256 digest can only be a mistake.
	setStatus(t, obj, map[string]any{"tokenHash": "not-a-sha-256-digest"})
	assertRejected(t, k8sClient.Status().Update(context.Background(), obj))
}

func setStatus(t *testing.T, obj *unstructured.Unstructured, status map[string]any) {
	t.Helper()

	if err := unstructured.SetNestedMap(obj.Object, status, "status"); err != nil {
		t.Fatalf("setting the status: %v", err)
	}
}
