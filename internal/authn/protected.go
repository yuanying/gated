package authn

import (
	"net/http"
	"time"

	"github.com/go-logr/logr"

	"github.com/yuanying/gated/internal/routing"
)

// HandoffParam carries the handoff token back to a protected host.
const HandoffParam = "t"

// Protected is the part of the login that runs on a protected host: it starts
// one, and it accepts the answer.
//
// Nothing about a session exists on the central authentication host. What
// crosses between them is a token good for seconds, at one host, and only in
// the browser that started the login.
type Protected struct {
	// Keys hands out the signing key. Required.
	Keys KeySource
	// Sessions issues the cookie a completed login ends in. Required.
	Sessions *Sessions
	// Now reads the clock. Nil means time.Now.
	Now func() time.Time
	// Log records refused handoffs.
	Log logr.Logger
}

// StartLogin prepares a response that is about to send a visitor to the
// central authentication host, and returns the value that ties the answer to
// this browser.
//
// The browser keeps the nonce; only its digest travels. That is what makes the
// token that comes back useless to anybody who reads it out of a URL, and
// usable once: the callback spends the nonce by clearing the cookie.
func (p *Protected) StartLogin(w http.ResponseWriter, r *http.Request) string {
	nonce, err := NewNonce()
	if err != nil {
		// Without randomness there is no way to bind the login. Say so
		// and start one that is not bound rather than none at all.
		p.Log.Error(err, "could not start a login", "host", r.Host)
		return ""
	}
	http.SetCookie(w, LoginCookie(nonce))
	return BindingFor(nonce)
}

// ServeHTTP is the callback a completed login returns to (ADR 0018). It turns
// a handoff into this host's own session cookie.
func (p *Protected) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	host := routing.CanonicalHost(r.Host)
	log := p.Log.WithValues("host", host)

	key, err := p.Keys.SigningKey(r.Context())
	if err != nil {
		log.Error(err, "a login came back before the signing key could be read")
		http.Error(w, "this login cannot be completed just now; try again", http.StatusServiceUnavailable)
		return
	}

	token, err := Verify(key, r.URL.Query().Get(HandoffParam), Expect{
		Kind: KindHandoff, Audience: host, Now: p.now(),
	})
	if err != nil {
		log.Info("a handoff was refused", "reason", err.Error())
		http.Error(w, "this login could not be completed; start again", http.StatusForbidden)
		return
	}

	// The nonce is spent whatever happens next, so that a handoff cannot be
	// offered twice even if what follows fails.
	nonce := ""
	if cookie, err := r.Cookie(LoginCookieName); err == nil {
		nonce = cookie.Value
	}
	http.SetCookie(w, ClearLoginCookie())

	if !MatchesBinding(nonce, token.Binding) {
		log.Info("a handoff was offered by a browser that did not start the login")
		http.Error(w, "this login did not start in this browser; start again", http.StatusForbidden)
		return
	}

	if err := p.Sessions.Issue(r.Context(), w, host, token.Subject); err != nil {
		log.Error(err, "issuing a session")
		http.Error(w, "this login cannot be completed just now; try again", http.StatusServiceUnavailable)
		return
	}

	// Next was checked when the handoff was signed and again by Verify, and
	// it is a path rather than an address, so this cannot leave the host.
	next := token.Next
	if CheckPath(next) != nil {
		next = "/"
	}
	log.V(1).Info("logged in", "subject", token.Subject)
	http.Redirect(w, r, next, http.StatusFound)
}

func (p *Protected) now() time.Time {
	if p.Now == nil {
		return time.Now()
	}
	return p.Now()
}
