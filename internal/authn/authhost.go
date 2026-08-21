package authn

import (
	"crypto/subtle"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"

	"github.com/yuanying/gated/internal/authn/connector"
	"github.com/yuanying/gated/internal/proxy"
	"github.com/yuanying/gated/internal/routing"
)

// The central authentication host (ADR 0003).
//
// Every login is collected here, so each identity provider is registered with
// exactly one callback URL and publishing a protected host never involves the
// provider's settings page. Nothing is stored: what leaves this host is a
// signed token good for seconds, at one host, in one browser.

// IdPCallbackPrefix is where a provider returns the visitor. The provider's
// name is part of the path, so a code meant for one application can never be
// exchanged at another's callback.
const IdPCallbackPrefix = ReservedPrefix + "idp/"

// ProviderParam names which provider a visitor chose.
const ProviderParam = "provider"

// The lifetimes of the two tokens the login uses.
const (
	// stateTTL is how long a visitor has to get through the provider.
	stateTTL = 10 * time.Minute
	// handoffTTL is deliberately tiny. This token travels in a URL, so it
	// is in a browser's history and possibly in a referrer.
	handoffTTL = 30 * time.Second
)

// IdPCallbackPath is where the named provider returns the visitor.
func IdPCallbackPath(provider string) string {
	return IdPCallbackPrefix + provider + "/callback"
}

// Hosts is the routing table's opinion on which hosts exist.
//
// The login will only return a visitor to a host something routes. Checking on
// the way back rather than on the way out is deliberate (ADR 0018): a check
// made where the address is built means nothing, because the address can be
// written by hand.
type Hosts interface {
	HasHost(host string) bool
}

// AuthHost answers the login flow on the central authentication host.
type AuthHost struct {
	// Host is the name this handler answers as. Required.
	Host string
	// Keys hands out the signing key. Required.
	Keys KeySource
	// Connectors are the identity providers on offer. Required.
	Connectors *connector.Set
	// Hosts bounds where a visitor may be returned to. Required.
	Hosts Hosts
	// Now reads the clock. Nil means time.Now.
	Now func() time.Time
	// Log records what happened to a login.
	Log logr.Logger
}

func (a *AuthHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Every answer here is about one visitor and one login in progress.
	w.Header().Set("Cache-Control", "no-store")

	if r.URL.Path == LoginPath {
		a.login(w, r)
		return
	}
	if provider, ok := providerOf(r.URL.Path); ok {
		a.callback(w, r, provider)
		return
	}
	http.NotFound(w, r)
}

// providerOf reads the provider's name out of a callback path.
func providerOf(path string) (string, bool) {
	rest, found := strings.CutPrefix(path, IdPCallbackPrefix)
	if !found {
		return "", false
	}
	name, found := strings.CutSuffix(rest, "/callback")
	if !found || name == "" || strings.Contains(name, "/") {
		return "", false
	}
	return name, true
}

// login starts a round trip, remembering where the visitor was going.
func (a *AuthHost) login(w http.ResponseWriter, r *http.Request) {
	next, err := a.destination(r.URL.Query().Get(proxy.NextParam))
	if err != nil {
		a.Log.V(1).Info("a login named somewhere it cannot send anybody", "reason", err.Error())
		http.Error(w, "that is not somewhere this login can send you", http.StatusBadRequest)
		return
	}

	binding := r.URL.Query().Get(proxy.BindParam)
	if binding == "" {
		// Reached without a browser to bind the answer to: a bookmark,
		// or somebody's history. Send the visitor to what they asked
		// for, which starts a login that can be bound.
		a.Log.V(1).Info("a login arrived unbound; sending it back to start", "next", next.String())
		http.Redirect(w, r, next.String(), http.StatusFound)
		return
	}

	provider, ok := a.provider(w, r, next, binding)
	if !ok {
		return
	}

	nonce, err := NewNonce()
	if err != nil {
		a.Log.Error(err, "could not start a login")
		http.Error(w, "this login cannot be started just now; try again", http.StatusInternalServerError)
		return
	}
	key, err := a.Keys.SigningKey(r.Context())
	if err != nil {
		a.Log.Error(err, "a login was started before the signing key could be read")
		http.Error(w, "this login cannot be started just now; try again", http.StatusServiceUnavailable)
		return
	}

	now := a.now()
	state, err := Sign(key, Token{
		Kind:      KindState,
		Subject:   nonce,
		Audience:  routing.CanonicalHost(a.Host),
		Next:      next.String(),
		Binding:   binding,
		Provider:  provider.Name(),
		IssuedAt:  now,
		ExpiresAt: now.Add(stateTTL),
	})
	if err != nil {
		a.Log.Error(err, "could not start a login")
		http.Error(w, "this login cannot be started just now; try again", http.StatusInternalServerError)
		return
	}

	away, err := provider.AuthCodeURL(r.Context(), connector.Request{
		RedirectURI: a.redirectURI(provider.Name()),
		State:       state,
		// The provider echoes this in the ID token, which ties the
		// token to this login rather than to any login.
		Nonce: BindingFor(nonce),
	})
	if err != nil {
		a.Log.Error(err, "could not reach the identity provider", "provider", provider.Name())
		http.Error(w, "the identity provider cannot be reached just now; try again", http.StatusBadGateway)
		return
	}

	// Matched at the callback: a state parameter obtained somewhere else
	// cannot complete a login in this browser.
	http.SetCookie(w, StateCookie(nonce))
	http.Redirect(w, r, away, http.StatusFound)
}

// callback is where the provider returns, with a code, a state and nothing
// else.
func (a *AuthHost) callback(w http.ResponseWriter, r *http.Request, name string) {
	query := r.URL.Query()
	log := a.Log.WithValues("provider", name)

	provider, ok := a.Connectors.Lookup(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if reported := query.Get("error"); reported != "" {
		log.Info("the identity provider refused the login", "error", reported)
		http.Error(w, "the identity provider did not complete this login", http.StatusForbidden)
		return
	}

	key, err := a.Keys.SigningKey(r.Context())
	if err != nil {
		log.Error(err, "a login came back before the signing key could be read")
		http.Error(w, "this login cannot be completed just now; try again", http.StatusServiceUnavailable)
		return
	}
	state, err := Verify(key, query.Get("state"), Expect{
		Kind: KindState, Audience: a.Host, Now: a.now(),
	})
	if err != nil {
		log.Info("a login came back with a state parameter gated did not issue", "reason", err.Error())
		http.Error(w, "this login could not be completed; start again", http.StatusForbidden)
		return
	}
	if state.Provider != name {
		log.Info("a login came back at the wrong provider's callback", "issuedFor", state.Provider)
		http.Error(w, "this login could not be completed; start again", http.StatusForbidden)
		return
	}

	// Spent whatever happens next.
	cookie, cookieErr := r.Cookie(StateCookieName)
	http.SetCookie(w, ClearStateCookie())
	if cookieErr != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state.Subject)) != 1 {
		log.Info("a login came back in a browser that did not start it")
		http.Error(w, "this login did not start in this browser; start again", http.StatusForbidden)
		return
	}

	identity, err := provider.Identify(r.Context(), query.Get("code"), connector.Request{
		RedirectURI: a.redirectURI(name),
		State:       query.Get("state"),
		Nonce:       BindingFor(state.Subject),
	})
	if err != nil {
		log.Error(err, "the identity provider would not say who this is")
		http.Error(w, "the identity provider would not say who you are", http.StatusBadGateway)
		return
	}
	if identity.Subject == "" {
		log.Info("the identity provider named nobody")
		http.Error(w, "the identity provider would not say who you are", http.StatusBadGateway)
		return
	}

	// Where the visitor was going is checked again. The routing table may
	// have changed while they were away, and a host that no longer exists
	// is one gated must not hand a session to.
	next, err := a.destination(state.Next)
	if err != nil {
		log.Info("the host this login was for is no longer routed", "reason", err.Error())
		http.Error(w, "that host is no longer published here", http.StatusNotFound)
		return
	}

	now := a.now()
	handoff, err := Sign(key, Token{
		Kind:      KindHandoff,
		Subject:   identity.Subject,
		Audience:  next.Host,
		Next:      next.RequestURI(),
		Binding:   state.Binding,
		IssuedAt:  now,
		ExpiresAt: now.Add(handoffTTL),
	})
	if err != nil {
		log.Error(err, "could not complete a login")
		http.Error(w, "this login cannot be completed just now; try again", http.StatusInternalServerError)
		return
	}

	back := &url.URL{
		Scheme:   "https",
		Host:     next.Host,
		Path:     CallbackPath,
		RawQuery: url.Values{HandoffParam: {handoff}}.Encode(),
	}
	log.V(1).Info("login completed", "subject", identity.Subject, "host", next.Host)
	http.Redirect(w, r, back.String(), http.StatusFound)
}

// destination decides whether an address is somewhere this login may return a
// visitor to.
//
// Only an https address on a host the routing table knows qualifies, and never
// this host: sending a completed login back to the login is a loop with
// nothing at the end of it. This is the whole of the open-redirect defence
// (ADR 0018).
func (a *AuthHost) destination(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("no destination was named")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%q is not an address", raw)
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("%q is not an absolute https address", raw)
	}
	host := routing.CanonicalHost(u.Host)
	if host == routing.CanonicalHost(a.Host) {
		return nil, fmt.Errorf("%q is the login itself", raw)
	}
	if a.Hosts == nil || !a.Hosts.HasHost(host) {
		return nil, fmt.Errorf("%q is not published here", u.Host)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	if err := CheckPath(u.Path); err != nil {
		return nil, err
	}
	u.Host = host
	u.Fragment = ""
	return u, nil
}

// provider settles which identity provider this login uses, answering the
// visitor itself when there is a choice to make or nothing to choose from.
func (a *AuthHost) provider(w http.ResponseWriter, r *http.Request, next *url.URL, binding string) (connector.Connector, bool) {
	if name := r.URL.Query().Get(ProviderParam); name != "" {
		provider, ok := a.Connectors.Lookup(name)
		if !ok {
			a.Log.V(1).Info("a login named a provider that is not configured", "provider", name)
			http.Error(w, "that is not a way to log in here", http.StatusBadRequest)
			return nil, false
		}
		return provider, true
	}
	if only, ok := a.Connectors.Only(); ok {
		return only, true
	}
	if a.Connectors.Len() == 0 {
		// Refusing to start without a provider is the configuration's
		// job (ADR 0009); if it is somehow empty, say so plainly.
		a.Log.Info("a login arrived with no identity provider configured")
		http.Error(w, "this installation has no way to log anybody in", http.StatusServiceUnavailable)
		return nil, false
	}
	a.chooser(w, next, binding)
	return nil, false
}

// chooser is the one page gated renders: a list of the providers on offer.
func (a *AuthHost) chooser(w http.ResponseWriter, next *url.URL, binding string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	page := new(strings.Builder)
	page.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
	page.WriteString("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
	page.WriteString("<title>Sign in</title></head><body><h1>Sign in</h1>")
	fmt.Fprintf(page, "<p>to continue to %s</p><ul>", html.EscapeString(next.Host))
	for _, name := range a.Connectors.Names() {
		target := LoginPath + "?" + url.Values{
			proxy.NextParam: {next.String()},
			proxy.BindParam: {binding},
			ProviderParam:   {name},
		}.Encode()
		fmt.Fprintf(page, "<li><a href=\"%s\">%s</a></li>", html.EscapeString(target), html.EscapeString(name))
	}
	page.WriteString("</ul></body></html>")
	w.Write([]byte(page.String()))
}

// redirectURI is the one address each provider is told to return to.
//
// The host is spelled as configured, port and all: this string has to match
// what was registered with the provider byte for byte, so the port cannot be
// dropped the way a comparison would drop it.
func (a *AuthHost) redirectURI(provider string) string {
	return "https://" + strings.ToLower(strings.TrimSuffix(a.Host, ".")) + IdPCallbackPath(provider)
}

func (a *AuthHost) now() time.Time {
	if a.Now == nil {
		return time.Now()
	}
	return a.Now()
}
