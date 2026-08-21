package authn

import (
	"net/http"
	"testing"
	"time"
)

// TestCookiesAreScopedToTheHostThatIssuedThem is ADR 0003's central rule about
// cookies. Widening one to the parent domain would send it to every host in
// the domain, which is the arrangement the ADR looked at and refused.
func TestCookiesAreScopedToTheHostThatIssuedThem(t *testing.T) {
	tests := map[string]struct {
		cookie   *http.Cookie
		wantName string
		wantPath string
	}{
		"the session": {
			cookie:   SessionCookie("value", time.Hour),
			wantName: SessionCookieName,
			wantPath: "/",
		},
		"the login nonce": {
			cookie:   LoginCookie("value"),
			wantName: LoginCookieName,
			wantPath: CallbackPath,
		},
		"the OAuth state nonce": {
			cookie:   StateCookie("value"),
			wantName: StateCookieName,
			wantPath: ReservedPrefix,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			c := tc.cookie
			if c.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", c.Name, tc.wantName)
			}
			if c.Domain != "" {
				t.Errorf("Domain = %q; a cookie must stay on the host that issued it (ADR 0003)", c.Domain)
			}
			if c.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q", c.Path, tc.wantPath)
			}
			if !c.HttpOnly {
				t.Error("HttpOnly is not set (ADR 0003)")
			}
			if !c.Secure {
				t.Error("Secure is not set (ADR 0003)")
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Errorf("SameSite = %v, want Lax (ADR 0003)", c.SameSite)
			}
			if c.MaxAge <= 0 {
				t.Errorf("MaxAge = %d, want a positive lifetime", c.MaxAge)
			}
		})
	}
}

// TestClearedCookiesAreExpired checks the other half: a cookie gated is done
// with has to actually leave the browser, which is what makes a login nonce
// single-use.
func TestClearedCookiesAreExpired(t *testing.T) {
	for name, c := range map[string]*http.Cookie{
		"the session":     ClearSessionCookie(),
		"the login nonce": ClearLoginCookie(),
		"the state nonce": ClearStateCookie(),
	} {
		t.Run(name, func(t *testing.T) {
			if c.Value != "" {
				t.Errorf("Value = %q, want it emptied", c.Value)
			}
			if c.MaxAge >= 0 {
				t.Errorf("MaxAge = %d, want a negative value so the browser drops it", c.MaxAge)
			}
			if c.Domain != "" {
				t.Errorf("Domain = %q; clearing must name the same scope as issuing", c.Domain)
			}
		})
	}
}

// TestABindingRevealsNothingAboutItsNonce is what lets the digest travel
// through the central authentication host, and through the visitor's URL bar,
// without becoming as good as the nonce itself.
func TestABindingRevealsNothingAboutItsNonce(t *testing.T) {
	first, err := NewNonce()
	if err != nil {
		t.Fatalf("NewNonce() = %v", err)
	}
	second, err := NewNonce()
	if err != nil {
		t.Fatalf("NewNonce() = %v", err)
	}
	if first == second {
		t.Fatal("two nonces came out the same")
	}
	if len(first) < 16 {
		t.Errorf("a nonce is %d characters; that is not enough to be unguessable", len(first))
	}

	binding := BindingFor(first)
	if binding == "" || binding == first {
		t.Fatalf("BindingFor(%q) = %q; want a digest, not the nonce", first, binding)
	}
	if BindingFor(first) != binding {
		t.Error("BindingFor is not deterministic")
	}
	if BindingFor(second) == binding {
		t.Error("two nonces produced the same binding")
	}
	if BindingFor("") != "" {
		t.Error("an absent nonce produced a binding, so an absent cookie would match one")
	}
}

// TestMatchesBindingRefusesTheEasyForgeries covers the comparison the callback
// makes. Both sides being empty must not count as agreement, or a handoff with
// no binding would be accepted by a browser holding no nonce.
func TestMatchesBindingRefusesTheEasyForgeries(t *testing.T) {
	nonce, err := NewNonce()
	if err != nil {
		t.Fatalf("NewNonce() = %v", err)
	}
	other, err := NewNonce()
	if err != nil {
		t.Fatalf("NewNonce() = %v", err)
	}

	tests := map[string]struct {
		nonce   string
		binding string
		want    bool
	}{
		"the nonce that started this login": {nonce: nonce, binding: BindingFor(nonce), want: true},
		"a nonce from another login":        {nonce: other, binding: BindingFor(nonce)},
		"no nonce":                          {nonce: "", binding: BindingFor(nonce)},
		"no binding":                        {nonce: nonce, binding: ""},
		"neither":                           {nonce: "", binding: ""},
		"the nonce offered as the binding":  {nonce: nonce, binding: nonce},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := MatchesBinding(tc.nonce, tc.binding); got != tc.want {
				t.Errorf("MatchesBinding(%q, %q) = %v, want %v", tc.nonce, tc.binding, got, tc.want)
			}
		})
	}
}
