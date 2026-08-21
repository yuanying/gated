//go:build e2e

package e2e

import (
	"net/http"
	"testing"
)

// A NetworkRole sends an anonymous visitor to log in, and who they come back
// as decides whether they get through.
//
// The two halves of that sentence are the second and third bullets of the
// goal, and they are one test because they are one round trip: the login and
// the decision that follows it are the same request seen twice.
func TestLoginDecidesWhoGetsThrough(t *testing.T) {
	ctx := testContext(t, settleTimeout)

	// Both hosts need a certificate: the visitor is sent from one to the
	// other and back, over HTTPS each time.
	appChain := certificateFor(t, ctx, "app-tls")
	certificateFor(t, ctx, "auth-tls")
	roots := issuingRoots(t, appChain)

	applyObject(t, ctx, role("app-readers", "app", anyMethod()))
	applyObject(t, ctx, binding("app-readers", "app-readers", "github:allowed-user"))

	// The role reaches a replica through an informer, so "protected" is
	// true a moment after the object exists rather than at once.
	anonymous := caller(t, roots)
	waitFor(t, ctx, "the NetworkRole never took effect", func() bool {
		status, _ := get(t, anonymous, https(appHost, "/"), nil)
		return status == http.StatusUnauthorized
	})

	t.Run("a browser is sent to log in", func(t *testing.T) {
		// This client does not follow the redirect, so what is asserted
		// is where gated pointed it rather than where it ended up.
		status, _ := get(t, anonymous, https(appHost, "/"), browserHeader())
		if status != http.StatusFound {
			t.Fatalf("an anonymous browser was answered %d, want %d", status, http.StatusFound)
		}
	})

	t.Run("an allowed subject gets through", func(t *testing.T) {
		browser := visitor(t, roots, "allowed-user")

		status, body := get(t, browser, https(appHost, "/private"), browserHeader())
		if status != http.StatusOK {
			t.Fatalf("github:allowed-user was answered %d, want 200\n%s", status, body)
		}
		if !fromBackend(body) {
			t.Fatalf("github:allowed-user did not reach the application:\n%s", body)
		}

		// The session is a cookie, so the next request needs no login.
		status, _ = get(t, browser, https(appHost, "/again"), browserHeader())
		if status != http.StatusOK {
			t.Fatalf("the second request was answered %d, want 200", status)
		}
	})

	t.Run("a subject nobody granted anything to is refused", func(t *testing.T) {
		browser := visitor(t, roots, "denied-user")

		status, body := get(t, browser, https(appHost, "/private"), browserHeader())
		if status != http.StatusForbidden {
			t.Fatalf("github:denied-user was answered %d, want 403\n%s", status, body)
		}
		if fromBackend(body) {
			t.Fatalf("github:denied-user reached the application")
		}
	})
}

// An Ingress no NetworkRole names is served to anybody. Publishing is the
// common case and protecting is the exception, so the absence of a rule is
// not the absence of permission (ADR 0002).
func TestUnprotectedIngressIsOpen(t *testing.T) {
	ctx := testContext(t, settleTimeout)
	chain := certificateFor(t, ctx, "open-tls")

	status, body := get(t, caller(t, issuingRoots(t, chain)), https(openHost, "/"), browserHeader())
	if status != http.StatusOK {
		t.Fatalf("an unprotected host answered %d, want 200\n%s", status, body)
	}
}
