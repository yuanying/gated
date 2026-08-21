package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/yuanying/gated/internal/proxy"
)

// The cookies gated sets, and where each of them is sent.
//
// None of them carries a Domain. A cookie without one is returned to the host
// that set it and to nothing else, which is the whole point of collecting the
// login on one host and handing the result to another (ADR 0003): the parent
// domain is exactly the scope that decision refused.
const (
	// SessionCookieName holds the signed session on a protected host.
	SessionCookieName = "__gated_session"
	// LoginCookieName holds the nonce that ties a login in progress to the
	// browser that started it. It is set on the protected host and sent
	// only to that host's callback.
	LoginCookieName = "__gated_login"
	// StateCookieName holds the nonce behind the OAuth state parameter. It
	// is set on the central authentication host.
	StateCookieName = "__gated_state"
)

// ReservedPrefix is the path prefix gated answers on for its own sake
// (ADR 0018). Both login cookies are confined to it or below.
const ReservedPrefix = "/__gated/"

// The paths of the login flow, named where the redirect that points at them is
// built (ADR 0018) so that the two cannot drift apart.
const (
	// LoginPath is where the central authentication host takes over.
	LoginPath = proxy.LoginPath
	// CallbackPath is where a protected host is handed the result.
	CallbackPath = proxy.CallbackPath
)

// nonceCookieAge is how long a login may take. It covers a visit to the
// identity provider, including typing a password and a second factor.
const nonceCookieAge = 10 * time.Minute

// SessionCookie is the cookie that says who the visitor is on this host.
func SessionCookie(value string, ttl time.Duration) *http.Cookie {
	return cookie(SessionCookieName, value, "/", int(ttl.Seconds()))
}

// ClearSessionCookie removes the session from the browser.
func ClearSessionCookie() *http.Cookie {
	return cookie(SessionCookieName, "", "/", -1)
}

// LoginCookie holds the nonce a handoff is bound to. It is confined to the
// callback, which is the only place it is read.
func LoginCookie(nonce string) *http.Cookie {
	return cookie(LoginCookieName, nonce, CallbackPath, int(nonceCookieAge.Seconds()))
}

// ClearLoginCookie spends the nonce. Removing it is what makes a handoff
// usable once: a second attempt finds nothing to match against.
func ClearLoginCookie() *http.Cookie {
	return cookie(LoginCookieName, "", CallbackPath, -1)
}

// StateCookie holds the nonce behind one OAuth state parameter.
func StateCookie(nonce string) *http.Cookie {
	return cookie(StateCookieName, nonce, ReservedPrefix, int(nonceCookieAge.Seconds()))
}

// ClearStateCookie spends the state nonce.
func ClearStateCookie() *http.Cookie {
	return cookie(StateCookieName, "", ReservedPrefix, -1)
}

func cookie(name, value, path string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:  name,
		Value: value,
		Path:  path,
		// No Domain: host-only, deliberately (ADR 0003).
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		// Lax rather than Strict: the browser arrives at the callback
		// through a redirect from another host, and Strict would
		// withhold the nonce on exactly that navigation.
		SameSite: http.SameSiteLaxMode,
	}
}

// nonceSize is how much randomness a nonce carries.
const nonceSize = 16

// NewNonce returns an unguessable value to tie one login to one browser.
func NewNonce() (string, error) {
	b := make([]byte, nonceSize)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// BindingFor is what travels in place of a nonce.
//
// The digest goes out through the login URL, through the central
// authentication host and back in the handoff, all of which a visitor can
// read. Only the browser that started the login holds the nonce itself, so
// only that browser can complete it.
func BindingFor(nonce string) string {
	if nonce == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(nonce))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// MatchesBinding reports whether the nonce a browser returned is the one a
// handoff was issued against. Two absences are not a match: a handoff bound to
// nothing must not be accepted by a browser holding nothing.
func MatchesBinding(nonce, binding string) bool {
	if nonce == "" || binding == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(BindingFor(nonce)), []byte(binding)) == 1
}
