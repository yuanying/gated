package policy_test

import (
	"reflect"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	gatev1alpha1 "github.com/yuanying/gated/internal/apis/gate/v1alpha1"
	"github.com/yuanying/gated/internal/authz"
	"github.com/yuanying/gated/internal/policy"
)

// newRole builds a NetworkRole the way the API server would hand one back,
// with the schema defaults already applied.
func newRole(namespace, name string, target gatev1alpha1.TargetReference, rules ...gatev1alpha1.NetworkRoleRule) gatev1alpha1.NetworkRole {
	if target.Group == "" {
		target.Group = gatev1alpha1.TargetGroupNetworking
	}
	if target.Kind == "" {
		target.Kind = gatev1alpha1.TargetKindIngress
	}
	return gatev1alpha1.NetworkRole{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       gatev1alpha1.NetworkRoleSpec{TargetRef: target, Rules: rules},
	}
}

func newBinding(namespace, name, roleName string, subjects ...string) gatev1alpha1.NetworkRoleBinding {
	b := gatev1alpha1.NetworkRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: gatev1alpha1.NetworkRoleBindingSpec{
			RoleRef: gatev1alpha1.RoleReference{Name: roleName},
		},
	}
	for _, s := range subjects {
		b.Spec.Subjects = append(b.Spec.Subjects, gatev1alpha1.Subject{
			Kind: gatev1alpha1.SubjectKindUser,
			Name: s,
		})
	}
	return b
}

func TestTargetKey(t *testing.T) {
	tests := []struct {
		name  string
		role  gatev1alpha1.NetworkRole
		want  types.NamespacedName
		wantR bool
	}{
		{
			// The common case is a role beside the Ingress it
			// protects, so the namespace may be left out.
			name:  "a bare name means the Ingress in the role's own namespace",
			role:  newRole("shop", "owner", gatev1alpha1.TargetReference{Name: "storefront"}),
			want:  types.NamespacedName{Namespace: "shop", Name: "storefront"},
			wantR: true,
		},
		{
			name:  "an explicit namespace is kept",
			role:  newRole("policies", "owner", gatev1alpha1.TargetReference{Namespace: "shop", Name: "storefront"}),
			want:  types.NamespacedName{Namespace: "shop", Name: "storefront"},
			wantR: true,
		},
		{
			// The schema refuses these, but the decision must not
			// depend on admission having been in force when the
			// object was written.
			name:  "a kind gated cannot resolve names nothing",
			role:  newRole("shop", "owner", gatev1alpha1.TargetReference{Kind: "HTTPRoute", Name: "storefront"}),
			wantR: false,
		},
		{
			name:  "a group gated cannot resolve names nothing",
			role:  newRole("shop", "owner", gatev1alpha1.TargetReference{Group: "gateway.networking.k8s.io", Name: "storefront"}),
			wantR: false,
		},
		{
			name:  "no name at all names nothing",
			role:  newRole("shop", "owner", gatev1alpha1.TargetReference{}),
			wantR: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := policy.TargetKey(&tc.role)
			if ok != tc.wantR {
				t.Fatalf("TargetKey() resolvable = %v, want %v", ok, tc.wantR)
			}
			if ok && got != tc.want {
				t.Errorf("TargetKey() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHosts(t *testing.T) {
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "storefront"},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{Host: "shop.example.com"},
				{Host: "www.example.com"},
				{Host: "shop.example.com"},
				{Host: ""},
			},
			TLS: []networkingv1.IngressTLS{
				{Hosts: []string{"shop.example.com", "tls-only.example.com"}},
			},
		},
	}

	want := []string{"shop.example.com", "tls-only.example.com", "www.example.com"}
	if got := policy.Hosts(ing); !reflect.DeepEqual(got, want) {
		t.Errorf("Hosts() = %v, want %v", got, want)
	}

	if got := policy.Hosts(&networkingv1.Ingress{}); len(got) != 0 {
		t.Errorf("Hosts(catch-all Ingress) = %v, want nothing", got)
	}
}

func TestBuild(t *testing.T) {
	storefront := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "storefront"},
	}
	ingresses := []networkingv1.Ingress{storefront}

	tests := []struct {
		name         string
		roles        []gatev1alpha1.NetworkRole
		bindings     []gatev1alpha1.NetworkRoleBinding
		wantRoles    []authz.Role
		wantBindings []authz.Binding
	}{
		{
			name: "a resolved role carries its target and rules",
			roles: []gatev1alpha1.NetworkRole{newRole("shop", "public",
				gatev1alpha1.TargetReference{Name: "storefront"},
				gatev1alpha1.NetworkRoleRule{
					Paths:   []string{"/", "/items/*"},
					Methods: []gatev1alpha1.HTTPMethod{"GET", "HEAD"},
				},
			)},
			wantRoles: []authz.Role{{
				Namespace: "shop",
				Name:      "public",
				Target:    authz.ResourceRef{Namespace: "shop", Name: "storefront"},
				Rules: []authz.Rule{{
					Paths:   []string{"/", "/items/*"},
					Methods: []string{"GET", "HEAD"},
				}},
			}},
		},
		{
			// The role is kept, without a target. It protects
			// nothing, which is exactly what the decision has to be
			// told so it can let the request through — and what the
			// role's status has to say out loud.
			name: "a role whose target is missing keeps no target",
			roles: []gatev1alpha1.NetworkRole{newRole("shop", "typo",
				gatev1alpha1.TargetReference{Name: "storefrnot"},
				gatev1alpha1.NetworkRoleRule{Paths: []string{"*"}, Methods: []gatev1alpha1.HTTPMethod{"*"}},
			)},
			wantRoles: []authz.Role{{
				Namespace: "shop",
				Name:      "typo",
				Rules:     []authz.Rule{{Paths: []string{"*"}, Methods: []string{"*"}}},
			}},
		},
		{
			name: "a role naming a kind gated cannot resolve keeps no target",
			roles: []gatev1alpha1.NetworkRole{newRole("shop", "future",
				gatev1alpha1.TargetReference{Kind: "HTTPRoute", Name: "storefront"},
			)},
			wantRoles: []authz.Role{{Namespace: "shop", Name: "future"}},
		},
		{
			// A role in one namespace may name an Ingress in
			// another; the schema allows it and the resolution
			// follows what was written.
			name: "a role may point across namespaces",
			roles: []gatev1alpha1.NetworkRole{newRole("policies", "central",
				gatev1alpha1.TargetReference{Namespace: "shop", Name: "storefront"},
			)},
			wantRoles: []authz.Role{{
				Namespace: "policies",
				Name:      "central",
				Target:    authz.ResourceRef{Namespace: "shop", Name: "storefront"},
			}},
		},
		{
			name:      "bindings carry their subjects",
			bindings:  []gatev1alpha1.NetworkRoleBinding{newBinding("shop", "owners", "public", "github:octocat", "system:authenticated")},
			wantRoles: []authz.Role{},
			wantBindings: []authz.Binding{{
				Namespace: "shop",
				RoleName:  "public",
				Subjects:  []string{"github:octocat", "system:authenticated"},
			}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotRoles, gotBindings := policy.Build(tc.roles, tc.bindings, ingresses)

			wantRoles := tc.wantRoles
			if wantRoles == nil {
				wantRoles = []authz.Role{}
			}
			if !reflect.DeepEqual(gotRoles, wantRoles) {
				t.Errorf("roles = %+v, want %+v", gotRoles, wantRoles)
			}
			wantBindings := tc.wantBindings
			if wantBindings == nil {
				wantBindings = []authz.Binding{}
			}
			if !reflect.DeepEqual(gotBindings, wantBindings) {
				t.Errorf("bindings = %+v, want %+v", gotBindings, wantBindings)
			}
		})
	}
}

// TestBuildFeedsTheDecision is the join the two halves have to agree on: what
// Build produces has to be what the decision reads, or the pure function is
// correct about inputs nobody ever hands it.
func TestBuildFeedsTheDecision(t *testing.T) {
	ingresses := []networkingv1.Ingress{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "storefront"},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{Host: "shop.example.com"}},
		},
	}}
	roles := []gatev1alpha1.NetworkRole{
		newRole("shop", "public", gatev1alpha1.TargetReference{Name: "storefront"},
			gatev1alpha1.NetworkRoleRule{Paths: []string{"*"}, Methods: []gatev1alpha1.HTTPMethod{"GET"}}),
		newRole("shop", "owner", gatev1alpha1.TargetReference{Name: "storefront"},
			gatev1alpha1.NetworkRoleRule{Paths: []string{"*"}, Methods: []gatev1alpha1.HTTPMethod{"*"}}),
	}
	bindings := []gatev1alpha1.NetworkRoleBinding{
		newBinding("shop", "everyone", "public", gatev1alpha1.SubjectUnauthenticated),
		newBinding("shop", "owners", "owner", "github:octocat"),
	}

	policies := authz.BuildPolicySet(policy.Build(roles, bindings, ingresses))

	target := authz.ResourceRef{Namespace: "shop", Name: "storefront"}
	req := func(subject, method string) authz.Request {
		return authz.Request{Subject: subject, Host: "shop.example.com", Path: "/", Method: method, Target: target}
	}

	for _, tc := range []struct {
		req  authz.Request
		want authz.Decision
	}{
		{req("", "GET"), authz.Allow},
		{req("", "POST"), authz.RequireLogin},
		{req("github:octocat", "POST"), authz.Allow},
		{req("github:hubot", "POST"), authz.Deny},
	} {
		if got := policies.Evaluate(tc.req); got != tc.want {
			t.Errorf("Evaluate(%s %s as %q) = %v, want %v", tc.req.Method, tc.req.Path, tc.req.Subject, got, tc.want)
		}
	}
}
