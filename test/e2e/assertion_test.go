//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yuanying/gated/internal/assertion/assertiontest"
)

// A backend can tell, from the request alone, whom gated authenticated for it:
// a logged-in visitor arrives with an assertion that verifies against the keys
// the central authentication host publishes, an anonymous one arrives with
// none, and nothing a client sends under the Gated- prefix arrives at all
// (ADR 0034).
func TestTheBackendIsToldWhoGatedAuthenticated(t *testing.T) {
	ctx := testContext(t, settleTimeout)

	appChain := certificateFor(t, ctx, "app-tls")
	certificateFor(t, ctx, "auth-tls")
	certificateFor(t, ctx, "open-tls")
	roots := issuingRoots(t, appChain)

	applyObject(t, ctx, role("assertion-readers", "app", anyMethod()))
	applyObject(t, ctx, binding("assertion-readers", "assertion-readers", "github:allowed-user"))

	anonymous := caller(t, roots)
	waitFor(t, ctx, "the NetworkRole never took effect", func() bool {
		status, _ := get(t, anonymous, https(appHost, "/"), nil)
		return status == http.StatusUnauthorized
	})

	// What a backend fetches, from where it is told to: the central
	// authentication host, never the request.
	status, jwks := get(t, anonymous, https(authHost, "/__gated/jwks.json"), nil)
	if status != http.StatusOK {
		t.Fatalf("the key set was answered %d, want 200\n%s", status, jwks)
	}

	// Whatever a client claims under the prefix, it claims for nothing.
	forged := browserHeader()
	forged.Set("Gated-Assertion", "forged")
	forged.Set("Gated-Subject", "github:admin")

	t.Run("a logged-in visitor is vouched for", func(t *testing.T) {
		browser := visitor(t, roots, "allowed-user")

		status, body := get(t, browser, https(appHost, "/private"), forged)
		if status != http.StatusOK || !fromBackend(body) {
			t.Fatalf("github:allowed-user was answered %d, want 200 from the application\n%s", status, body)
		}
		if got := echoed(body, "Gated-Subject"); len(got) != 0 {
			t.Errorf("the client's own Gated-Subject reached the application: %v", got)
		}

		signed := echoed(body, "Gated-Assertion")
		if len(signed) != 1 {
			t.Fatalf("the application saw %d Gated-Assertion headers, want 1:\n%s", len(signed), body)
		}
		claims, err := assertiontest.Verify([]byte(jwks), signed[0], assertiontest.Expect{
			Issuer:   "https://" + authHost,
			Audience: appHost,
			Now:      time.Now(),
		})
		if err != nil {
			t.Fatalf("the assertion does not verify against the published keys: %v", err)
		}
		if claims.Subject != "github:allowed-user" {
			t.Errorf("the assertion vouches for %q, want github:allowed-user", claims.Subject)
		}
	})

	t.Run("an anonymous visitor is vouched for by nobody", func(t *testing.T) {
		// Let through because nothing protects the host, which is
		// exactly the case a backend checking for itself is meant to
		// catch.
		status, body := get(t, caller(t, roots), https(openHost, "/"), forged)
		if status != http.StatusOK || !fromBackend(body) {
			t.Fatalf("an unprotected host answered %d, want 200 from the application\n%s", status, body)
		}
		for _, name := range []string{"Gated-Assertion", "Gated-Subject"} {
			if got := echoed(body, name); len(got) != 0 {
				t.Errorf("an anonymous request reached the application with %s %v", name, got)
			}
		}
	})
}

// echoed returns the values the stand-in application reported for one header.
func echoed(body, name string) []string {
	var values []string
	for line := range strings.SplitSeq(body, "\n") {
		if value, ok := strings.CutPrefix(line, "header "+name+"="); ok {
			values = append(values, value)
		}
	}
	return values
}
