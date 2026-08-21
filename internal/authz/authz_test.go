package authz_test

import (
	"testing"

	"github.com/yuanying/gated/internal/authz"
)

// The decision made here is the one place where a mistake does not show up as
// a failure. A wrong Deny is reported by whoever is locked out; a wrong Allow
// is reported by nobody. So the branches are enumerated rather than sampled.

// refs used throughout. Nothing here names a real deployment.
var (
	shop  = authz.ResourceRef{Namespace: "shop", Name: "storefront"}
	admin = authz.ResourceRef{Namespace: "shop", Name: "admin"}
)

const (
	octocat = "github:octocat"
	hubot   = "github:hubot"
	mona    = "google:mona@example.com"
)

// role is a NetworkRole that resolved its target.
func role(name string, target authz.ResourceRef, rules ...authz.Rule) authz.Role {
	return authz.Role{Namespace: target.Namespace, Name: name, Target: target, Rules: rules}
}

// rule spells one grant of paths and methods.
func rule(paths []string, methods []string) authz.Rule {
	return authz.Rule{Paths: paths, Methods: methods}
}

// bind grants a role to subjects in the role's own namespace.
func bind(namespace, roleName string, subjects ...string) authz.Binding {
	return authz.Binding{Namespace: namespace, RoleName: roleName, Subjects: subjects}
}

// request is a request against the storefront unless a case says otherwise.
func request(subject, method, path string, target authz.ResourceRef) authz.Request {
	return authz.Request{
		Subject: subject,
		Host:    "shop.example.com",
		Path:    path,
		Method:  method,
		Target:  target,
	}
}

func TestEvaluate(t *testing.T) {
	// readOnlyToEveryone lets anyone read, logged in or not.
	readOnlyToEveryone := []authz.Role{role("public", shop, rule([]string{"*"}, []string{"GET"}))}

	tests := []struct {
		name     string
		roles    []authz.Role
		bindings []authz.Binding
		req      authz.Request
		want     authz.Decision
	}{
		{
			// ADR 0002: a resource no NetworkRole names is not
			// protected, and is served without authentication.
			name: "no role names the target at all",
			req:  request("", "GET", "/", shop),
			want: authz.Allow,
		},
		{
			name:  "no role names the target, and the caller is logged in",
			roles: []authz.Role{role("elsewhere", admin, rule([]string{"*"}, []string{"*"}))},
			req:   request(octocat, "POST", "/orders", shop),
			want:  authz.Allow,
		},
		{
			// The reference did not resolve, so nothing is
			// protected. This is the fail-open hole that the status
			// on the role exists to make visible.
			name:  "the role's target did not resolve",
			roles: []authz.Role{{Namespace: "shop", Name: "broken", Rules: []authz.Rule{rule([]string{"*"}, []string{"*"})}}},
			req:   request("", "GET", "/", shop),
			want:  authz.Allow,
		},
		{
			// A role names the target but nothing is bound to it:
			// the target is protected and nobody may in.
			name:  "a role protects the target with no binding",
			roles: readOnlyToEveryone,
			req:   request("", "GET", "/", shop),
			want:  authz.Deny,
		},
		{
			name:     "a role with no rules protects and grants nothing",
			roles:    []authz.Role{role("empty", shop)},
			bindings: []authz.Binding{bind("shop", "empty", octocat)},
			req:      request(octocat, "GET", "/", shop),
			want:     authz.Deny,
		},
		{
			name:     "anonymous read is granted to everyone",
			roles:    readOnlyToEveryone,
			bindings: []authz.Binding{bind("shop", "public", "system:unauthenticated")},
			req:      request("", "GET", "/", shop),
			want:     authz.Allow,
		},
		{
			// The reason RequireLogin exists: someone could pass
			// here, so the caller is sent to log in rather than
			// refused outright.
			name:     "a named subject may pass, so an anonymous caller is sent to log in",
			roles:    []authz.Role{role("owner", shop, rule([]string{"*"}, []string{"*"}))},
			bindings: []authz.Binding{bind("shop", "owner", octocat)},
			req:      request("", "GET", "/", shop),
			want:     authz.RequireLogin,
		},
		{
			name:     "a logged in caller who is not the named subject is refused",
			roles:    []authz.Role{role("owner", shop, rule([]string{"*"}, []string{"*"}))},
			bindings: []authz.Binding{bind("shop", "owner", octocat)},
			req:      request(hubot, "GET", "/", shop),
			want:     authz.Deny,
		},
		{
			name:     "the named subject passes",
			roles:    []authz.Role{role("owner", shop, rule([]string{"*"}, []string{"*"}))},
			bindings: []authz.Binding{bind("shop", "owner", octocat)},
			req:      request(octocat, "DELETE", "/orders/1", shop),
			want:     authz.Allow,
		},
		{
			name:     "a google subject is matched in full",
			roles:    []authz.Role{role("owner", shop, rule([]string{"*"}, []string{"*"}))},
			bindings: []authz.Binding{bind("shop", "owner", mona)},
			req:      request(mona, "GET", "/", shop),
			want:     authz.Allow,
		},
		{
			// system:authenticated is anyone who has logged in,
			// which nobody has yet.
			name:     "system:authenticated sends an anonymous caller to log in",
			roles:    []authz.Role{role("members", shop, rule([]string{"*"}, []string{"*"}))},
			bindings: []authz.Binding{bind("shop", "members", "system:authenticated")},
			req:      request("", "GET", "/", shop),
			want:     authz.RequireLogin,
		},
		{
			name:     "system:authenticated lets any logged in caller through",
			roles:    []authz.Role{role("members", shop, rule([]string{"*"}, []string{"*"}))},
			bindings: []authz.Binding{bind("shop", "members", "system:authenticated")},
			req:      request(hubot, "POST", "/", shop),
			want:     authz.Allow,
		},
		{
			// The case ADR 0007 names: read is public, writing is
			// not granted to anyone at all, so logging in cannot
			// help and the answer is a refusal rather than a login.
			name:     "GET is public and POST is granted to nobody",
			roles:    readOnlyToEveryone,
			bindings: []authz.Binding{bind("shop", "public", "system:unauthenticated")},
			req:      request("", "POST", "/", shop),
			want:     authz.Deny,
		},
		{
			name:     "GET is public and POST is granted to nobody, for a logged in caller too",
			roles:    readOnlyToEveryone,
			bindings: []authz.Binding{bind("shop", "public", "system:unauthenticated")},
			req:      request(octocat, "POST", "/", shop),
			want:     authz.Deny,
		},
		{
			// Two roles over the same target: the union of what
			// they allow, which is what ADR 0002 asks for.
			name: "public reads and owner writes are unioned",
			roles: []authz.Role{
				role("public", shop, rule([]string{"*"}, []string{"GET"})),
				role("owner", shop, rule([]string{"*"}, []string{"*"})),
			},
			bindings: []authz.Binding{
				bind("shop", "public", "system:unauthenticated"),
				bind("shop", "owner", octocat),
			},
			req:  request(octocat, "POST", "/", shop),
			want: authz.Allow,
		},
		{
			name: "an anonymous write against the union is sent to log in",
			roles: []authz.Role{
				role("public", shop, rule([]string{"*"}, []string{"GET"})),
				role("owner", shop, rule([]string{"*"}, []string{"*"})),
			},
			bindings: []authz.Binding{
				bind("shop", "public", "system:unauthenticated"),
				bind("shop", "owner", octocat),
			},
			req:  request("", "POST", "/", shop),
			want: authz.RequireLogin,
		},
		{
			name: "an anonymous read against the union passes without logging in",
			roles: []authz.Role{
				role("public", shop, rule([]string{"*"}, []string{"GET"})),
				role("owner", shop, rule([]string{"*"}, []string{"*"})),
			},
			bindings: []authz.Binding{
				bind("shop", "public", "system:unauthenticated"),
				bind("shop", "owner", octocat),
			},
			req:  request("", "GET", "/", shop),
			want: authz.Allow,
		},
		{
			name:     "two subjects on one binding",
			roles:    []authz.Role{role("owner", shop, rule([]string{"*"}, []string{"*"}))},
			bindings: []authz.Binding{bind("shop", "owner", octocat, hubot)},
			req:      request(hubot, "GET", "/", shop),
			want:     authz.Allow,
		},
		{
			name:  "two bindings of the same role",
			roles: []authz.Role{role("owner", shop, rule([]string{"*"}, []string{"*"}))},
			bindings: []authz.Binding{
				bind("shop", "owner", octocat),
				bind("shop", "owner", hubot),
			},
			req:  request(hubot, "GET", "/", shop),
			want: authz.Allow,
		},
		{
			// The policy of one target says nothing about another.
			name: "a grant on another target does not carry over",
			roles: []authz.Role{
				role("shop-public", shop, rule([]string{"*"}, []string{"*"})),
				role("admin-owner", admin, rule([]string{"*"}, []string{"*"})),
			},
			bindings: []authz.Binding{
				bind("shop", "shop-public", "system:unauthenticated"),
				bind("shop", "admin-owner", octocat),
			},
			req:  request("", "GET", "/", admin),
			want: authz.RequireLogin,
		},
		{
			// A binding reaches only the role beside it. Reaching
			// across a namespace would let a binding open up
			// something its author does not own.
			name:     "a binding in another namespace does not grant",
			roles:    []authz.Role{role("owner", shop, rule([]string{"*"}, []string{"*"}))},
			bindings: []authz.Binding{bind("other", "owner", "system:unauthenticated")},
			req:      request("", "GET", "/", shop),
			want:     authz.Deny,
		},
		{
			name:     "a binding naming a role that does not exist grants nothing",
			roles:    []authz.Role{role("owner", shop, rule([]string{"*"}, []string{"*"}))},
			bindings: []authz.Binding{bind("shop", "typo", "system:unauthenticated")},
			req:      request("", "GET", "/", shop),
			want:     authz.Deny,
		},
		{
			name:     "a binding with no subjects grants nothing",
			roles:    []authz.Role{role("owner", shop, rule([]string{"*"}, []string{"*"}))},
			bindings: []authz.Binding{bind("shop", "owner")},
			req:      request(octocat, "GET", "/", shop),
			want:     authz.Deny,
		},

		// The path vocabulary is the one RBAC uses for nonResourceURLs
		// (ADR 0010): an exact path, a path ending in "*", or "*".
		{
			name:     "an exact path matches only itself",
			roles:    []authz.Role{role("p", shop, rule([]string{"/metrics"}, []string{"GET"}))},
			bindings: []authz.Binding{bind("shop", "p", "system:unauthenticated")},
			req:      request("", "GET", "/metrics", shop),
			want:     authz.Allow,
		},
		{
			name:     "an exact path does not match a longer one",
			roles:    []authz.Role{role("p", shop, rule([]string{"/metrics"}, []string{"GET"}))},
			bindings: []authz.Binding{bind("shop", "p", "system:unauthenticated")},
			req:      request("", "GET", "/metrics/cpu", shop),
			want:     authz.Deny,
		},
		{
			name:     "an exact path does not match a shorter one",
			roles:    []authz.Role{role("p", shop, rule([]string{"/metrics"}, []string{"GET"}))},
			bindings: []authz.Binding{bind("shop", "p", "system:unauthenticated")},
			req:      request("", "GET", "/", shop),
			want:     authz.Deny,
		},
		{
			name:     "a trailing star matches what follows it",
			roles:    []authz.Role{role("p", shop, rule([]string{"/api/*"}, []string{"GET"}))},
			bindings: []authz.Binding{bind("shop", "p", "system:unauthenticated")},
			req:      request("", "GET", "/api/v1/items", shop),
			want:     authz.Allow,
		},
		{
			name:     "a trailing star matches the prefix itself",
			roles:    []authz.Role{role("p", shop, rule([]string{"/api/*"}, []string{"GET"}))},
			bindings: []authz.Binding{bind("shop", "p", "system:unauthenticated")},
			req:      request("", "GET", "/api/", shop),
			want:     authz.Allow,
		},
		{
			name:     "a trailing star does not match a sibling path",
			roles:    []authz.Role{role("p", shop, rule([]string{"/api/*"}, []string{"GET"}))},
			bindings: []authz.Binding{bind("shop", "p", "system:unauthenticated")},
			req:      request("", "GET", "/apiary", shop),
			want:     authz.Deny,
		},
		{
			name:     "a star on its own matches every path",
			roles:    []authz.Role{role("p", shop, rule([]string{"*"}, []string{"GET"}))},
			bindings: []authz.Binding{bind("shop", "p", "system:unauthenticated")},
			req:      request("", "GET", "/anything/at/all", shop),
			want:     authz.Allow,
		},
		{
			name:     "one rule may list several paths",
			roles:    []authz.Role{role("p", shop, rule([]string{"/a", "/b"}, []string{"GET"}))},
			bindings: []authz.Binding{bind("shop", "p", "system:unauthenticated")},
			req:      request("", "GET", "/b", shop),
			want:     authz.Allow,
		},
		{
			name: "a role may carry several rules",
			roles: []authz.Role{role("p", shop,
				rule([]string{"/a"}, []string{"GET"}),
				rule([]string{"/b"}, []string{"POST"}),
			)},
			bindings: []authz.Binding{bind("shop", "p", "system:unauthenticated")},
			req:      request("", "POST", "/b", shop),
			want:     authz.Allow,
		},
		{
			// The path is compared as it arrived. Routing does not
			// normalise it either (ADR 0012), so what was authorised
			// and what is forwarded are the same string.
			name:     "the path is compared as it arrived",
			roles:    []authz.Role{role("p", shop, rule([]string{"/a"}, []string{"GET"}))},
			bindings: []authz.Binding{bind("shop", "p", "system:unauthenticated")},
			req:      request("", "GET", "/a/", shop),
			want:     authz.Deny,
		},

		// Methods are upper-case names or "*".
		{
			name:     "a star matches every method",
			roles:    []authz.Role{role("p", shop, rule([]string{"*"}, []string{"*"}))},
			bindings: []authz.Binding{bind("shop", "p", "system:unauthenticated")},
			req:      request("", "PATCH", "/", shop),
			want:     authz.Allow,
		},
		{
			name:     "one rule may list several methods",
			roles:    []authz.Role{role("p", shop, rule([]string{"*"}, []string{"GET", "HEAD"}))},
			bindings: []authz.Binding{bind("shop", "p", "system:unauthenticated")},
			req:      request("", "HEAD", "/", shop),
			want:     authz.Allow,
		},
		{
			// GET does not imply HEAD. A rule that means both says
			// both, the way RBAC makes a verb list say each verb.
			name:     "GET does not carry HEAD with it",
			roles:    []authz.Role{role("p", shop, rule([]string{"*"}, []string{"GET"}))},
			bindings: []authz.Binding{bind("shop", "p", "system:unauthenticated")},
			req:      request("", "HEAD", "/", shop),
			want:     authz.Deny,
		},
		{
			// HTTP methods are case sensitive, and the rule
			// vocabulary is upper case. Folding case here would
			// grant more than what was written.
			name:     "a lower case method does not match",
			roles:    []authz.Role{role("p", shop, rule([]string{"*"}, []string{"GET"}))},
			bindings: []authz.Binding{bind("shop", "p", "system:unauthenticated")},
			req:      request("", "get", "/", shop),
			want:     authz.Deny,
		},
		{
			// Paths and methods are ANDed inside one rule: a rule
			// covering /a with GET says nothing about POST /a.
			name: "paths and methods must both match the same rule",
			roles: []authz.Role{role("p", shop,
				rule([]string{"/a"}, []string{"GET"}),
				rule([]string{"/b"}, []string{"POST"}),
			)},
			bindings: []authz.Binding{bind("shop", "p", "system:unauthenticated")},
			req:      request("", "POST", "/a", shop),
			want:     authz.Deny,
		},
		{
			// Nothing was routed, so nothing is protected. The
			// proxy answers 404 before this is ever asked, but a
			// total function is one less way to be surprised.
			name:     "a request with no target is not protected",
			roles:    []authz.Role{role("owner", shop, rule([]string{"*"}, []string{"*"}))},
			bindings: []authz.Binding{bind("shop", "owner", octocat)},
			req:      request("", "GET", "/", authz.ResourceRef{}),
			want:     authz.Allow,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policies := authz.BuildPolicySet(tc.roles, tc.bindings)
			if got := policies.Evaluate(tc.req); got != tc.want {
				t.Errorf("Evaluate(%+v) = %v, want %v", tc.req, got, tc.want)
			}
		})
	}
}

// TestEvaluateDoesNotDependOnOrder is the executable form of "the rules never
// deny" (ADR 0002). If any ordering of the inputs changed an answer, some rule
// would be overriding another, and the outcome would depend on which replica
// listed the objects in which order.
func TestEvaluateDoesNotDependOnOrder(t *testing.T) {
	roles := []authz.Role{
		role("public", shop, rule([]string{"*"}, []string{"GET"})),
		role("owner", shop, rule([]string{"*"}, []string{"*"})),
		role("members", shop, rule([]string{"/members/*"}, []string{"GET", "POST"})),
		role("empty", shop),
	}
	bindings := []authz.Binding{
		bind("shop", "public", "system:unauthenticated"),
		bind("shop", "owner", octocat),
		bind("shop", "members", "system:authenticated"),
		bind("shop", "empty", hubot),
	}

	requests := []authz.Request{
		request("", "GET", "/", shop),
		request("", "POST", "/", shop),
		request("", "POST", "/members/x", shop),
		request(hubot, "POST", "/members/x", shop),
		request(hubot, "DELETE", "/", shop),
		request(octocat, "DELETE", "/", shop),
	}

	want := make([]authz.Decision, len(requests))
	base := authz.BuildPolicySet(roles, bindings)
	for i, req := range requests {
		want[i] = base.Evaluate(req)
	}

	for _, perm := range permutations(len(roles)) {
		shuffledRoles := make([]authz.Role, len(roles))
		shuffledBindings := make([]authz.Binding, len(bindings))
		for to, from := range perm {
			shuffledRoles[to] = roles[from]
			shuffledBindings[to] = bindings[from]
		}
		policies := authz.BuildPolicySet(shuffledRoles, shuffledBindings)
		for i, req := range requests {
			if got := policies.Evaluate(req); got != want[i] {
				t.Fatalf("order %v: Evaluate(%+v) = %v, want %v", perm, req, got, want[i])
			}
		}
	}
}

// permutations lists every ordering of n items.
func permutations(n int) [][]int {
	if n == 0 {
		return [][]int{{}}
	}
	var out [][]int
	for _, rest := range permutations(n - 1) {
		for at := 0; at <= len(rest); at++ {
			with := make([]int, 0, n)
			with = append(with, rest[:at]...)
			with = append(with, n-1)
			with = append(with, rest[at:]...)
			out = append(out, with)
		}
	}
	return out
}

// TestProtects is what the proxy and the status writers both need to know:
// whether anything at all claims to protect a target.
func TestProtects(t *testing.T) {
	policies := authz.BuildPolicySet(
		[]authz.Role{
			role("owner", shop, rule([]string{"*"}, []string{"*"})),
			{Namespace: "shop", Name: "broken", Rules: []authz.Rule{rule([]string{"*"}, []string{"*"})}},
		},
		[]authz.Binding{bind("shop", "owner", octocat)},
	)

	if !policies.Protects(shop) {
		t.Error("Protects(storefront) = false, want true: a role names it")
	}
	if policies.Protects(admin) {
		t.Error("Protects(admin) = true, want false: no role names it")
	}
	if policies.Protects(authz.ResourceRef{}) {
		t.Error("Protects(zero) = true, want false")
	}
}

// TestNilPolicySet pins what an empty world means. It is Allow, because "no
// NetworkRole names this" is exactly the fail-open case — which is also why
// the caller must not reach here before the first snapshot has been built.
func TestNilPolicySet(t *testing.T) {
	var policies *authz.PolicySet
	if got := policies.Evaluate(request("", "GET", "/", shop)); got != authz.Allow {
		t.Errorf("(*PolicySet)(nil).Evaluate() = %v, want %v", got, authz.Allow)
	}
	if policies.Protects(shop) {
		t.Error("(*PolicySet)(nil).Protects() = true, want false")
	}
}

// TestBuildPolicySetCopiesItsInput keeps a snapshot a snapshot: whoever built
// it may reuse the slices afterwards without the policy in force changing
// underneath a request.
func TestBuildPolicySetCopiesItsInput(t *testing.T) {
	rules := []authz.Rule{rule([]string{"*"}, []string{"GET"})}
	roles := []authz.Role{role("public", shop, rules...)}
	bindings := []authz.Binding{bind("shop", "public", "system:unauthenticated")}

	policies := authz.BuildPolicySet(roles, bindings)
	if got := policies.Evaluate(request("", "GET", "/", shop)); got != authz.Allow {
		t.Fatalf("Evaluate() = %v, want %v", got, authz.Allow)
	}

	rules[0].Methods[0] = "POST"
	roles[0].Rules[0].Paths[0] = "/nowhere"
	bindings[0].Subjects[0] = hubot

	if got := policies.Evaluate(request("", "GET", "/", shop)); got != authz.Allow {
		t.Errorf("after mutating the input, Evaluate() = %v, want %v", got, authz.Allow)
	}
}

func TestDecisionString(t *testing.T) {
	for _, tc := range []struct {
		decision authz.Decision
		want     string
	}{
		{authz.Allow, "Allow"},
		{authz.Deny, "Deny"},
		{authz.RequireLogin, "RequireLogin"},
	} {
		if got := tc.decision.String(); got != tc.want {
			t.Errorf("Decision(%d).String() = %q, want %q", tc.decision, got, tc.want)
		}
	}
}
