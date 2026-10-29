//go:build envtest

package envtest_test

import (
	"testing"
)

func TestNetworkRoleBindingDefaults(t *testing.T) {
	ns := newNamespace(t)
	got := mustCreate(t, ns, `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRoleBinding
metadata:
  name: minimal
spec:
  roleRef:
    name: minimal
  subjects:
    - name: github:octocat
`)

	// User is the only kind there is, so writing it every time would be
	// noise.
	subjects, found, err := nestedSlice(got, "spec", "subjects")
	if err != nil || !found {
		t.Fatalf("spec.subjects: found=%v err=%v", found, err)
	}
	if kind := subjects[0].(map[string]any)["kind"]; kind != "User" {
		t.Errorf("spec.subjects[0].kind = %v, want %q", kind, "User")
	}
}

func TestNetworkRoleBindingAcceptsTheSubjectVocabulary(t *testing.T) {
	ns := newNamespace(t)

	mustCreate(t, ns, `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRoleBinding
metadata:
  name: vocabulary
spec:
  roleRef:
    name: minimal
  subjects:
    - kind: User
      name: github:octocat
    - kind: User
      name: google:someone@example.com
    - kind: User
      name: system:authenticated
    - kind: User
      name: system:unauthenticated
    - kind: User
      name: system:serviceaccount:natsumi:assistant
    - kind: User
      name: system:serviceaccount:release-lag:release-lag.v2
`)
}

func TestNetworkRoleBindingRejectsInvalidSpecs(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
	}{
		{
			name: "roleRef without a name",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRoleBinding
metadata:
  name: no-role-name
spec:
  roleRef: {}
  subjects:
    - name: github:octocat
`,
		},
		{
			name: "no roleRef at all",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRoleBinding
metadata:
  name: no-role
spec:
  subjects:
    - name: github:octocat
`,
		},
		{
			name: "no subjects",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRoleBinding
metadata:
  name: no-subjects
spec:
  roleRef:
    name: minimal
  subjects: []
`,
		},
		{
			// Groups are deliberately absent for now (ADR 0002). A
			// binding that names one must fail loudly rather than
			// grant nothing.
			name: "a Group subject",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRoleBinding
metadata:
  name: group-subject
spec:
  roleRef:
    name: minimal
  subjects:
    - kind: Group
      name: github:some-org
`,
		},
		{
			// The provider prefix is what tells GitHub's octocat
			// from Google's; a bare name would silently match
			// neither.
			name: "a subject without a provider prefix",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRoleBinding
metadata:
  name: bare-subject
spec:
  roleRef:
    name: minimal
  subjects:
    - name: octocat
`,
		},
		{
			name: "an unknown provider prefix",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRoleBinding
metadata:
  name: unknown-provider
spec:
  roleRef:
    name: minimal
  subjects:
    - name: gitlab:octocat
`,
		},
		{
			name: "a google subject that is not a mail address",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRoleBinding
metadata:
  name: google-not-mail
spec:
  roleRef:
    name: minimal
  subjects:
    - name: google:someone
`,
		},
		{
			name: "a system subject that does not exist",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRoleBinding
metadata:
  name: unknown-system-subject
spec:
  roleRef:
    name: minimal
  subjects:
    - name: system:masters
`,
		},
		{
			// The group of every ServiceAccount in a namespace is
			// not a subject gated has (ADR 0002, ADR 0039).
			name: "the service accounts of a namespace",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRoleBinding
metadata:
  name: serviceaccounts-group
spec:
  roleRef:
    name: minimal
  subjects:
    - name: system:serviceaccounts:natsumi
`,
		},
		{
			name: "a service account without a name",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRoleBinding
metadata:
  name: serviceaccount-no-name
spec:
  roleRef:
    name: minimal
  subjects:
    - name: system:serviceaccount:natsumi
`,
		},
		{
			name: "a service account in a namespace that cannot exist",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRoleBinding
metadata:
  name: serviceaccount-bad-namespace
spec:
  roleRef:
    name: minimal
  subjects:
    - name: system:serviceaccount:Natsumi:assistant
`,
		},
		{
			name: "an empty subject name",
			manifest: `
apiVersion: gate.unstable.cloud/v1alpha1
kind: NetworkRoleBinding
metadata:
  name: empty-subject
spec:
  roleRef:
    name: minimal
  subjects:
    - name: ""
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
