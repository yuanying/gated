package proxy_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yuanying/gated/internal/authz"
	"github.com/yuanying/gated/internal/proxy"
	"github.com/yuanying/gated/internal/routing"
)

// The middleware is the other half of ADR 0002: the pure function says Allow,
// Deny or RequireLogin, and everything about how that reaches the client —
// which status code, a redirect or a challenge, and whether the caller is a
// browser at all — is decided out here, where an *http.Request exists.

// staticSubject is the seam stage 6 fills: it answers who is behind a request.
type staticSubject string

func (s staticSubject) Subject(*http.Request) string { return string(s) }

const protectedHost = "shop.example.com"

var protectedIngress = routing.ResourceRef{Namespace: "shop", Name: "storefront"}

// policiesFor builds a store holding one snapshot.
func policiesFor(t *testing.T, roles []authz.Role, bindings []authz.Binding) *proxy.PolicyStore {
	t.Helper()
	store := &proxy.PolicyStore{}
	store.Store(authz.BuildPolicySet(roles, bindings))
	return store
}

// ownerOnly protects the storefront and grants everything to one account.
func ownerOnly() ([]authz.Role, []authz.Binding) {
	return []authz.Role{{
		Namespace: "shop",
		Name:      "owner",
		Target:    authz.ResourceRef{Namespace: "shop", Name: "storefront"},
		Rules:     []authz.Rule{{Paths: []string{"*"}, Methods: []string{"*"}}},
	}}, []authz.Binding{{
		Namespace: "shop",
		RoleName:  "owner",
		Subjects:  []string{"github:octocat"},
	}}
}

// serve runs one request through the middleware with a routed match already in
// the context, the way the proxy hands it over.
func serve(t *testing.T, a *proxy.Authorization, req *http.Request, match *routing.Match) *http.Response {
	t.Helper()

	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		io.WriteString(w, "from the backend")
	})

	handler := a.Wrap(next)
	rec := httptest.NewRecorder()
	if match != nil {
		req = proxy.RequestWithMatch(req, *match)
	}
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	if reached && resp.StatusCode != http.StatusOK {
		t.Fatalf("the backend was reached but the status is %d", resp.StatusCode)
	}
	return resp
}

func newRequest(method, path string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(method, "https://"+protectedHost+path, nil)
	req.Host = protectedHost
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// browser is what a browser asks for when it navigates to a page.
var browser = map[string]string{
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
}

// apiClient is what curl and most programs send.
var apiClient = map[string]string{"Accept": "*/*"}

func TestAuthorizationAllows(t *testing.T) {
	roles, bindings := ownerOnly()
	a := &proxy.Authorization{
		Policies: policiesFor(t, roles, bindings),
		Subjects: staticSubject("github:octocat"),
		AuthHost: "auth.example.com",
	}

	resp := serve(t, a, newRequest(http.MethodGet, "/", browser), &routing.Match{Ingress: protectedIngress})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "from the backend" {
		t.Errorf("body = %q, want the backend's", body)
	}
}

func TestAuthorizationLetsUnprotectedResourcesThrough(t *testing.T) {
	roles, bindings := ownerOnly()
	a := &proxy.Authorization{
		Policies: policiesFor(t, roles, bindings),
		AuthHost: "auth.example.com",
	}

	// A different Ingress: nothing names it, so it is not protected.
	other := &routing.Match{Ingress: routing.ResourceRef{Namespace: "shop", Name: "blog"}}
	resp := serve(t, a, newRequest(http.MethodGet, "/", browser), other)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status for an unprotected resource = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestAuthorizationRedirectsBrowsersToLogin covers the reason RequireLogin is
// not simply a refusal: a person who has not logged in yet is sent somewhere
// they can (ADR 0002).
func TestAuthorizationRedirectsBrowsersToLogin(t *testing.T) {
	roles, bindings := ownerOnly()
	a := &proxy.Authorization{
		Policies: policiesFor(t, roles, bindings),
		AuthHost: "auth.example.com",
	}

	resp := serve(t, a, newRequest(http.MethodGet, "/orders?page=2", browser), &routing.Match{Ingress: protectedIngress})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	location := resp.Header.Get("Location")
	want := "https://auth.example.com/__gated/login?next=https%3A%2F%2Fshop.example.com%2Forders%3Fpage%3D2"
	if location != want {
		t.Errorf("Location = %q, want %q", location, want)
	}
	if resp.Header.Get("Cache-Control") == "" {
		t.Error("a login redirect must not be cached, but no Cache-Control was set")
	}
}

// TestAuthorizationChallengesNonBrowsers is the other half of the same rule:
// sending a program a 302 to a login page tells it nothing it can act on.
func TestAuthorizationChallengesNonBrowsers(t *testing.T) {
	roles, bindings := ownerOnly()
	a := &proxy.Authorization{
		Policies: policiesFor(t, roles, bindings),
		AuthHost: "auth.example.com",
	}

	resp := serve(t, a, newRequest(http.MethodGet, "/orders", apiClient), &routing.Match{Ingress: protectedIngress})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if resp.Header.Get("Location") != "" {
		t.Error("a 401 carried a Location header")
	}
	// BASIC is the challenge because that is the path a token takes for
	// clients that cannot be changed (ADR 0004).
	if got := resp.Header.Get("WWW-Authenticate"); got != `Basic realm="gated"` {
		t.Errorf("WWW-Authenticate = %q, want %q", got, `Basic realm="gated"`)
	}
}

func TestAuthorizationRefusesAKnownCaller(t *testing.T) {
	roles, bindings := ownerOnly()
	a := &proxy.Authorization{
		Policies: policiesFor(t, roles, bindings),
		Subjects: staticSubject("github:hubot"),
		AuthHost: "auth.example.com",
	}

	// Logging in again cannot help, so this is a refusal even for a
	// browser: no redirect, no challenge.
	resp := serve(t, a, newRequest(http.MethodGet, "/", browser), &routing.Match{Ingress: protectedIngress})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if resp.Header.Get("Location") != "" {
		t.Error("a 403 carried a Location header")
	}
}

// TestAuthorizationWithoutASnapshotRefuses is the difference between "nothing
// is protected" and "nothing is loaded yet". The pure function cannot tell
// them apart — an empty set allows everything — so the store has to.
func TestAuthorizationWithoutASnapshotRefuses(t *testing.T) {
	a := &proxy.Authorization{Policies: &proxy.PolicyStore{}, AuthHost: "auth.example.com"}

	resp := serve(t, a, newRequest(http.MethodGet, "/", browser), &routing.Match{Ingress: protectedIngress})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status before the first snapshot = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}

	if err := a.Policies.Ready(nil); err == nil {
		t.Error("Ready() = nil before the first snapshot, want an error")
	}
	a.Policies.Store(authz.BuildPolicySet(nil, nil))
	if err := a.Policies.Ready(nil); err != nil {
		t.Errorf("Ready() = %v after the first snapshot, want nil", err)
	}
}

// TestAuthorizationWithoutARouteRefuses guards the same seam from the other
// side: the proxy answers 404 before this runs, so a request arriving here
// unrouted means the chain was wired wrongly.
func TestAuthorizationWithoutARouteRefuses(t *testing.T) {
	roles, bindings := ownerOnly()
	a := &proxy.Authorization{Policies: policiesFor(t, roles, bindings), AuthHost: "auth.example.com"}

	resp := serve(t, a, newRequest(http.MethodGet, "/", browser), nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status for an unrouted request = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
}

// TestAuthorizationWithNowhereToLogIn covers the misconfiguration: without a
// central authentication host there is nowhere to send anybody, so the answer
// is a challenge rather than a redirect to nowhere.
func TestAuthorizationWithNowhereToLogIn(t *testing.T) {
	roles, bindings := ownerOnly()
	a := &proxy.Authorization{Policies: policiesFor(t, roles, bindings)}

	resp := serve(t, a, newRequest(http.MethodGet, "/", browser), &routing.Match{Ingress: protectedIngress})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

// TestAuthorizationDoesNotRedirectTheAuthHostToItself keeps a
// misconfiguration from becoming a redirect loop.
func TestAuthorizationDoesNotRedirectTheAuthHostToItself(t *testing.T) {
	roles, bindings := ownerOnly()
	a := &proxy.Authorization{Policies: policiesFor(t, roles, bindings), AuthHost: protectedHost}

	resp := serve(t, a, newRequest(http.MethodGet, "/", browser), &routing.Match{Ingress: protectedIngress})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

// TestAuthorizationPassesTheSubjectOn lets whatever runs after the middleware
// — logging, and the token bookkeeping of a later stage — see who was decided
// about, without resolving the identity a second time.
func TestAuthorizationPassesTheSubjectOn(t *testing.T) {
	roles, bindings := ownerOnly()
	a := &proxy.Authorization{
		Policies: policiesFor(t, roles, bindings),
		Subjects: staticSubject("github:octocat"),
		AuthHost: "auth.example.com",
	}

	var seen string
	handler := a.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen, _ = proxy.SubjectFromContext(r.Context())
	}))
	req := proxy.RequestWithMatch(newRequest(http.MethodGet, "/", browser), routing.Match{Ingress: protectedIngress})
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if seen != "github:octocat" {
		t.Errorf("the subject seen downstream = %q, want %q", seen, "github:octocat")
	}
}

// TestAuthorizationReadsTheRequestAsItArrived pins the join between the
// decision and the request: the method and the path handed to the pure
// function are the ones the client sent, not a tidied version of them.
func TestAuthorizationReadsTheRequestAsItArrived(t *testing.T) {
	roles := []authz.Role{{
		Namespace: "shop",
		Name:      "public",
		Target:    authz.ResourceRef{Namespace: "shop", Name: "storefront"},
		Rules:     []authz.Rule{{Paths: []string{"/items/*"}, Methods: []string{"GET"}}},
	}}
	bindings := []authz.Binding{{Namespace: "shop", RoleName: "public", Subjects: []string{authz.SubjectUnauthenticated}}}
	a := &proxy.Authorization{Policies: policiesFor(t, roles, bindings), AuthHost: "auth.example.com"}

	for _, tc := range []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodGet, "/items/1", http.StatusOK},
		{http.MethodGet, "/items/1?q=x", http.StatusOK},
		{http.MethodHead, "/items/1", http.StatusForbidden},
		{http.MethodGet, "/orders", http.StatusForbidden},
	} {
		resp := serve(t, a, newRequest(tc.method, tc.path, apiClient), &routing.Match{Ingress: protectedIngress})
		if resp.StatusCode != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, resp.StatusCode, tc.want)
		}
	}
}

func TestWantsHTML(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		want   bool
	}{
		{"a browser navigating", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", true},
		{"html alone", "text/html", true},
		{"xhtml", "application/xhtml+xml", true},
		{"any text", "text/*", true},
		{"html with parameters", "text/html; charset=utf-8", true},
		{"html spelled loudly", "TEXT/HTML", true},
		// */* is what curl and most programs send. Reading it as a
		// browser would send every API client to a login page.
		{"anything at all", "*/*", false},
		{"no header", "", false},
		{"json", "application/json", false},
		{"an XHR asking for json first", "application/json, text/plain, */*", false},
		{"html explicitly refused", "text/html;q=0, */*", false},
		{"html refused among others", "application/json, text/html;q=0.0", false},
		{"nonsense", ",,;", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := proxy.WantsHTML(tc.accept); got != tc.want {
				t.Errorf("WantsHTML(%q) = %v, want %v", tc.accept, got, tc.want)
			}
		})
	}
}
