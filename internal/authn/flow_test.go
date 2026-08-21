package authn

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yuanying/gated/internal/authn/connector"
	"github.com/yuanying/gated/internal/proxy"
)

// The login as one thing: a protected host that starts it, a central
// authentication host that talks to the identity provider, and a handoff that
// comes back and becomes a cookie on the host the visitor asked for.
//
// The identity provider is a stub here. What it answers is somebody else's
// test; what matters at this level is that nothing but a completed round trip
// produces a cookie, and that the cookie lands on one host and nowhere else.

const (
	authHost  = "auth.example.com"
	shopHost  = "shop.example.com"
	otherHost = "wiki.example.com"
)

// knownHosts is the routing table's opinion on where a visitor may be sent
// back to (ADR 0018).
type knownHosts map[string]bool

func (k knownHosts) HasHost(host string) bool { return k[strings.ToLower(host)] }

// stubProvider stands in for GitHub or Google.
type stubProvider struct {
	name    string
	subject string
	err     error

	authorizeURL string
	seen         connector.Request
	code         string
}

func (p *stubProvider) Name() string { return p.name }

func (p *stubProvider) AuthCodeURL(_ context.Context, req connector.Request) (string, error) {
	p.seen = req
	base := p.authorizeURL
	if base == "" {
		base = "https://idp.example.net/authorize"
	}
	return base + "?state=" + url.QueryEscape(req.State), nil
}

func (p *stubProvider) Identify(_ context.Context, code string, req connector.Request) (connector.Identity, error) {
	p.code = code
	p.seen = req
	if p.err != nil {
		return connector.Identity{}, p.err
	}
	return connector.Identity{Subject: p.subject}, nil
}

// world is one gated process's worth of login machinery.
type world struct {
	keys      StaticKey
	hosts     knownHosts
	providers []connector.Connector
	now       time.Time

	auth      *AuthHost
	protected *Protected
	sessions  *Sessions
}

func newWorld(t *testing.T, providers ...connector.Connector) *world {
	t.Helper()
	if len(providers) == 0 {
		providers = []connector.Connector{&stubProvider{name: "github", subject: "github:octocat"}}
	}
	w := &world{
		keys:      StaticKey(testKey),
		hosts:     knownHosts{shopHost: true, otherHost: true, authHost: true},
		providers: providers,
		now:       testTime(),
	}
	clock := func() time.Time { return w.now }
	w.sessions = &Sessions{Keys: w.keys, TTL: 12 * time.Hour, Now: clock}
	w.auth = &AuthHost{
		Host:       authHost,
		Keys:       w.keys,
		Connectors: connector.NewSet(providers...),
		Hosts:      w.hosts,
		Now:        clock,
	}
	w.protected = &Protected{Keys: w.keys, Sessions: w.sessions, Now: clock}
	return w
}

// get runs one request through a handler and returns the response.
func get(h http.Handler, host, target string, cookies ...*http.Cookie) *http.Response {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Host = host
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Result()
}

// cookieNamed returns the cookie a response set, if it set one.
func cookieNamed(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestALoginRoundTripEndsInACookieOnOneHost is the flow of ADR 0003 end to
// end: the protected host starts it, the central host completes it with the
// provider, and the protected host is handed the result.
func TestALoginRoundTripEndsInACookieOnOneHost(t *testing.T) {
	w := newWorld(t)

	// The protected host starts the login and remembers the browser.
	start := httptest.NewRecorder()
	binding := w.protected.StartLogin(start, httptest.NewRequest(http.MethodGet, "https://"+shopHost+"/reports", nil))
	if binding == "" {
		t.Fatal("StartLogin() returned no binding")
	}
	nonce := cookieNamed(start.Result(), LoginCookieName)
	if nonce == nil {
		t.Fatal("StartLogin() set no login cookie")
	}

	// The central host sends the visitor to the provider.
	login := "https://" + authHost + LoginPath + "?" + url.Values{
		proxy.NextParam: {"https://" + shopHost + "/reports?page=2"},
		proxy.BindParam: {binding},
	}.Encode()
	resp := get(w.auth, authHost, login)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login: status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	away, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing the redirect: %v", err)
	}
	state := away.Query().Get("state")
	if state == "" {
		t.Fatal("the visitor was sent to the provider with no state parameter")
	}
	stateCookie := cookieNamed(resp, StateCookieName)
	if stateCookie == nil {
		t.Fatal("login set no state cookie, so the callback has nothing to match against")
	}

	// The provider returns to the central host.
	back := IdPCallbackPath("github") + "?" + url.Values{"code": {"the-code"}, "state": {state}}.Encode()
	resp = get(w.auth, authHost, back, stateCookie)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback: status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	handoff, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing the handoff redirect: %v", err)
	}
	if handoff.Host != shopHost {
		t.Fatalf("the visitor was handed to %q, want %q", handoff.Host, shopHost)
	}
	if handoff.Path != proxy.CallbackPath {
		t.Fatalf("the visitor was handed to %q, want %q", handoff.Path, proxy.CallbackPath)
	}

	// The protected host turns the handoff into its own cookie.
	resp = get(w.protected, shopHost, handoff.RequestURI(), nonce)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("handoff: status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if got, want := resp.Header.Get("Location"), "/reports?page=2"; got != want {
		t.Errorf("continued to %q, want %q", got, want)
	}
	session := cookieNamed(resp, SessionCookieName)
	if session == nil {
		t.Fatal("the callback issued no session cookie")
	}
	if session.Domain != "" {
		t.Errorf("the session cookie names the domain %q; it must stay on this host (ADR 0003)", session.Domain)
	}
	if cookieNamed(resp, LoginCookieName).MaxAge >= 0 {
		t.Error("the login nonce was not spent")
	}

	// And that cookie names the visitor on this host, and on no other.
	req := httptest.NewRequest(http.MethodGet, "https://"+shopHost+"/reports", nil)
	req.Host = shopHost
	req.AddCookie(session)
	if got := w.sessions.Subject(req); got != "github:octocat" {
		t.Errorf("Subject() = %q, want %q", got, "github:octocat")
	}
	elsewhere := httptest.NewRequest(http.MethodGet, "https://"+otherHost+"/", nil)
	elsewhere.Host = otherHost
	elsewhere.AddCookie(session)
	if got := w.sessions.Subject(elsewhere); got != "" {
		t.Errorf("the session for one host named %q on another", got)
	}
}

// completeLogin runs the round trip and returns the handoff URL and the login
// nonce the browser holds.
func completeLogin(t *testing.T, w *world, provider, next string) (string, *http.Cookie) {
	t.Helper()

	start := httptest.NewRecorder()
	binding := w.protected.StartLogin(start, httptest.NewRequest(http.MethodGet, next, nil))
	nonce := cookieNamed(start.Result(), LoginCookieName)

	login := "https://" + authHost + LoginPath + "?" + url.Values{
		proxy.NextParam: {next},
		proxy.BindParam: {binding},
		"provider":      {provider},
	}.Encode()
	resp := get(w.auth, authHost, login)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login: status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	away, _ := url.Parse(resp.Header.Get("Location"))
	stateCookie := cookieNamed(resp, StateCookieName)

	back := IdPCallbackPath(provider) + "?" + url.Values{
		"code": {"the-code"}, "state": {away.Query().Get("state")},
	}.Encode()
	resp = get(w.auth, authHost, back, stateCookie)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback: status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	handoff, _ := url.Parse(resp.Header.Get("Location"))
	return handoff.RequestURI(), nonce
}

// TestAHandoffCanOnlyBeSpentOnce is the property the binding buys. The token
// travels in a URL, so it is in a history and possibly a referrer; replaying
// it must not produce a second session.
func TestAHandoffCanOnlyBeSpentOnce(t *testing.T) {
	w := newWorld(t)
	handoff, nonce := completeLogin(t, w, "github", "https://"+shopHost+"/reports")

	if resp := get(w.protected, shopHost, handoff, nonce); resp.StatusCode != http.StatusFound {
		t.Fatalf("the first use: status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	// The browser no longer holds the nonce, because the callback cleared it.
	resp := get(w.protected, shopHost, handoff)
	if resp.StatusCode == http.StatusFound {
		t.Fatal("the handoff was spent twice")
	}
	if cookieNamed(resp, SessionCookieName) != nil {
		t.Error("a replayed handoff issued a session cookie")
	}
}

// TestAHandoffIsUselessToAnybodyElse covers the same token in another browser,
// which is what somebody who read it out of a log or a referrer would have.
func TestAHandoffIsUselessToAnybodyElse(t *testing.T) {
	w := newWorld(t)
	handoff, _ := completeLogin(t, w, "github", "https://"+shopHost+"/reports")

	other := httptest.NewRecorder()
	w.protected.StartLogin(other, httptest.NewRequest(http.MethodGet, "https://"+shopHost+"/", nil))
	somebodyElse := cookieNamed(other.Result(), LoginCookieName)

	for name, cookies := range map[string][]*http.Cookie{
		"with no nonce at all":       nil,
		"with somebody else's nonce": {somebodyElse},
	} {
		t.Run(name, func(t *testing.T) {
			resp := get(w.protected, shopHost, handoff, cookies...)
			if resp.StatusCode == http.StatusFound {
				t.Fatal("the handoff was accepted")
			}
			if cookieNamed(resp, SessionCookieName) != nil {
				t.Error("a session cookie was issued")
			}
		})
	}
}

func TestAHandoffIsRefusedElsewhere(t *testing.T) {
	w := newWorld(t)
	handoff, nonce := completeLogin(t, w, "github", "https://"+shopHost+"/reports")

	tests := map[string]struct {
		host    string
		advance time.Duration
	}{
		"offered to another host": {host: otherHost},
		"offered too late":        {host: shopHost, advance: time.Hour},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			w.now = testTime().Add(tc.advance)
			defer func() { w.now = testTime() }()

			resp := get(w.protected, tc.host, handoff, nonce)
			if resp.StatusCode == http.StatusFound {
				t.Fatal("the handoff was accepted")
			}
			if cookieNamed(resp, SessionCookieName) != nil {
				t.Error("a session cookie was issued")
			}
		})
	}
}

// TestTheHandoffIsShortLived keeps the window it can be replayed in from
// quietly growing into a session's.
func TestTheHandoffIsShortLived(t *testing.T) {
	w := newWorld(t)
	handoff, _ := completeLogin(t, w, "github", "https://"+shopHost+"/reports")

	raw, err := url.Parse(handoff)
	if err != nil {
		t.Fatalf("parsing the handoff: %v", err)
	}
	token, err := Verify(testKey, raw.Query().Get(HandoffParam), Expect{
		Kind: KindHandoff, Audience: shopHost, Now: w.now,
	})
	if err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	if life := token.ExpiresAt.Sub(token.IssuedAt); life > time.Minute {
		t.Errorf("the handoff is valid for %v; it travels in a URL, so it should be seconds", life)
	}
}

// TestTheLoginWillNotSendAVisitorAnywhere is the open-redirect check, which
// ADR 0018 put on the side that returns the visitor rather than the side that
// builds the address.
func TestTheLoginWillNotSendAVisitorAnywhere(t *testing.T) {
	w := newWorld(t)
	binding := BindingFor("a-nonce")

	tests := map[string]string{
		"a host nothing routes":            "https://elsewhere.example.net/",
		"a host that merely ends the same": "https://shop.example.com.evil.example.net/",
		"plain HTTP":                       "http://" + shopHost + "/",
		"a scheme-relative address":        "//elsewhere.example.net/",
		"a bare path":                      "/reports",
		"not a URL at all":                 "://",
		"nothing":                          "",
		"a data URL":                       "data:text/html,<script>alert(1)</script>",
		"back to the login itself":         "https://" + authHost + LoginPath,
	}

	for name, next := range tests {
		t.Run(name, func(t *testing.T) {
			target := LoginPath + "?" + url.Values{proxy.NextParam: {next}, proxy.BindParam: {binding}}.Encode()
			resp := get(w.auth, authHost, target)
			if resp.StatusCode == http.StatusFound {
				t.Fatalf("the visitor was sent to %q", resp.Header.Get("Location"))
			}
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
			}
		})
	}
}

// TestALoginWithNoBindingStartsAgain covers a login URL reached directly — a
// bookmark, or somebody's history — where there is no browser to bind to yet.
// Sending the visitor to the resource they named produces a proper start
// rather than a dead end.
func TestALoginWithNoBindingStartsAgain(t *testing.T) {
	w := newWorld(t)
	next := "https://" + shopHost + "/reports"

	resp := get(w.auth, authHost, LoginPath+"?"+url.Values{proxy.NextParam: {next}}.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if got := resp.Header.Get("Location"); got != next {
		t.Errorf("Location = %q, want %q", got, next)
	}
	if cookieNamed(resp, StateCookieName) != nil {
		t.Error("a login that cannot be bound started anyway")
	}
}

// TestTheStateParameterIsCheckedAgainstThisBrowser is the CSRF defence on the
// OAuth round trip: a state parameter somebody else obtained must not complete
// a login here.
func TestTheStateParameterIsCheckedAgainstThisBrowser(t *testing.T) {
	w := newWorld(t)
	next := "https://" + shopHost + "/reports"

	start := httptest.NewRecorder()
	binding := w.protected.StartLogin(start, httptest.NewRequest(http.MethodGet, next, nil))
	resp := get(w.auth, authHost, LoginPath+"?"+url.Values{
		proxy.NextParam: {next}, proxy.BindParam: {binding},
	}.Encode())
	away, _ := url.Parse(resp.Header.Get("Location"))
	state := away.Query().Get("state")
	stateCookie := cookieNamed(resp, StateCookieName)

	// A second login, whose cookie belongs to a different state.
	second := get(w.auth, authHost, LoginPath+"?"+url.Values{
		proxy.NextParam: {next}, proxy.BindParam: {binding},
	}.Encode())
	otherCookie := cookieNamed(second, StateCookieName)

	tests := map[string]struct {
		state  string
		cookie *http.Cookie
	}{
		"no state at all":               {cookie: stateCookie},
		"a state that was never issued": {state: "made up", cookie: stateCookie},
		"no cookie":                     {state: state},
		"the cookie of another login":   {state: state, cookie: otherCookie},
		"a state signed for something else": {state: mustSign(t, Token{
			Kind: KindState, Subject: "nonce", Audience: authHost,
			Next: next, Provider: "github",
			IssuedAt: testTime(), ExpiresAt: testTime().Add(time.Hour),
		}), cookie: stateCookie},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			target := IdPCallbackPath("github") + "?" + url.Values{
				"code": {"the-code"}, "state": {tc.state},
			}.Encode()
			var cookies []*http.Cookie
			if tc.cookie != nil {
				cookies = append(cookies, tc.cookie)
			}
			resp := get(w.auth, authHost, target, cookies...)
			if resp.StatusCode == http.StatusFound {
				t.Fatalf("the login completed anyway, to %q", resp.Header.Get("Location"))
			}
		})
	}
}

// TestAStateBelongsToOneProvider keeps a state issued for one provider from
// completing at another's callback, where a different application's code would
// be exchanged.
func TestAStateBelongsToOneProvider(t *testing.T) {
	w := newWorld(t,
		&stubProvider{name: "github", subject: "github:octocat"},
		&stubProvider{name: "google", subject: "google:someone@example.com"},
	)
	next := "https://" + shopHost + "/reports"

	start := httptest.NewRecorder()
	binding := w.protected.StartLogin(start, httptest.NewRequest(http.MethodGet, next, nil))
	resp := get(w.auth, authHost, LoginPath+"?"+url.Values{
		proxy.NextParam: {next}, proxy.BindParam: {binding}, "provider": {"github"},
	}.Encode())
	away, _ := url.Parse(resp.Header.Get("Location"))

	target := IdPCallbackPath("google") + "?" + url.Values{
		"code": {"the-code"}, "state": {away.Query().Get("state")},
	}.Encode()
	if resp := get(w.auth, authHost, target, cookieNamed(resp, StateCookieName)); resp.StatusCode == http.StatusFound {
		t.Fatal("a state issued for one provider completed at another")
	}
}

// TestAProviderThatRefusesEndsTheLogin covers the identity provider saying no,
// or saying nothing usable. Neither produces a session.
func TestAProviderThatRefusesEndsTheLogin(t *testing.T) {
	tests := map[string]connector.Connector{
		"the provider reported an error": &stubProvider{name: "github", err: errRefused},
		"the provider named nobody":      &stubProvider{name: "github", subject: ""},
	}

	for name, provider := range tests {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, provider)
			next := "https://" + shopHost + "/reports"

			start := httptest.NewRecorder()
			binding := w.protected.StartLogin(start, httptest.NewRequest(http.MethodGet, next, nil))
			resp := get(w.auth, authHost, LoginPath+"?"+url.Values{
				proxy.NextParam: {next}, proxy.BindParam: {binding},
			}.Encode())
			away, _ := url.Parse(resp.Header.Get("Location"))

			target := IdPCallbackPath("github") + "?" + url.Values{
				"code": {"the-code"}, "state": {away.Query().Get("state")},
			}.Encode()
			resp = get(w.auth, authHost, target, cookieNamed(resp, StateCookieName))
			if resp.StatusCode == http.StatusFound {
				t.Fatalf("the login completed anyway, to %q", resp.Header.Get("Location"))
			}
		})
	}
}

// TestTheProviderIsToldWhereToComeBack checks the one URL that has to be
// registered with the provider. It names the central host and the provider,
// and nothing about the host the visitor came from (ADR 0003).
func TestTheProviderIsToldWhereToComeBack(t *testing.T) {
	provider := &stubProvider{name: "github", subject: "github:octocat"}
	w := newWorld(t, provider)
	next := "https://" + shopHost + "/reports"

	start := httptest.NewRecorder()
	binding := w.protected.StartLogin(start, httptest.NewRequest(http.MethodGet, next, nil))
	get(w.auth, authHost, LoginPath+"?"+url.Values{
		proxy.NextParam: {next}, proxy.BindParam: {binding},
	}.Encode())

	want := "https://" + authHost + IdPCallbackPath("github")
	if provider.seen.RedirectURI != want {
		t.Errorf("redirect URI = %q, want %q", provider.seen.RedirectURI, want)
	}
	if strings.Contains(provider.seen.RedirectURI, shopHost) {
		t.Error("the redirect URI names the host the visitor came from, so every host would need registering")
	}
	if provider.seen.Nonce == "" {
		t.Error("the provider was asked for an ID token with no nonce to tie it to this login")
	}
}

// TestAVisitorChoosesBetweenProviders covers the one page gated renders.
func TestAVisitorChoosesBetweenProviders(t *testing.T) {
	w := newWorld(t,
		&stubProvider{name: "github", subject: "github:octocat"},
		&stubProvider{name: "google", subject: "google:someone@example.com"},
	)
	next := "https://" + shopHost + "/reports"
	target := LoginPath + "?" + url.Values{proxy.NextParam: {next}, proxy.BindParam: {BindingFor("n")}}.Encode()

	resp := get(w.auth, authHost, target)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body := readAll(t, resp)
	for _, want := range []string{"github", "google"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not offer %q", want)
		}
	}
	if resp.Header.Get("Cache-Control") == "" {
		t.Error("the page is cacheable, and it is about one login")
	}
}

// TestAnUnknownProviderIsRefused keeps the provider name in a URL from
// reaching anything but the configured set.
func TestAnUnknownProviderIsRefused(t *testing.T) {
	w := newWorld(t)
	next := "https://" + shopHost + "/reports"

	target := LoginPath + "?" + url.Values{
		proxy.NextParam: {next}, proxy.BindParam: {BindingFor("n")}, "provider": {"gitlab"},
	}.Encode()
	if resp := get(w.auth, authHost, target); resp.StatusCode == http.StatusFound {
		t.Fatalf("the visitor was sent to %q", resp.Header.Get("Location"))
	}
	if resp := get(w.auth, authHost, IdPCallbackPath("gitlab")+"?code=c&state=s"); resp.StatusCode == http.StatusFound {
		t.Fatal("an unknown provider's callback answered with a redirect")
	}
}

// TestTheRouterKeepsTheLoginOffTheApplication checks which requests gated
// answers itself and which it passes on.
func TestTheRouterKeepsTheLoginOffTheApplication(t *testing.T) {
	w := newWorld(t)
	forwarded := false
	router := &Router{
		AuthHost: authHost,
		Central:  w.auth,
		Callback: w.protected,
		Next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			forwarded = true
		}),
	}

	tests := map[string]struct {
		host          string
		path          string
		wantForwarded bool
	}{
		"the login on the central host":      {host: authHost, path: LoginPath},
		"a provider callback":                {host: authHost, path: IdPCallbackPath("github")},
		"anything else on the central host":  {host: authHost, path: "/", wantForwarded: true},
		"the callback on a protected host":   {host: shopHost, path: CallbackPath},
		"the login path on a protected host": {host: shopHost, path: LoginPath, wantForwarded: true},
		"an application path":                {host: shopHost, path: "/reports", wantForwarded: true},
		"a path that merely starts the same": {host: shopHost, path: CallbackPath + "/more", wantForwarded: true},
		"the central host named with a port": {host: authHost + ":443", path: LoginPath},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			forwarded = false
			get(router, tc.host, tc.path)
			if forwarded != tc.wantForwarded {
				t.Errorf("forwarded = %v, want %v", forwarded, tc.wantForwarded)
			}
		})
	}
}

// TestASessionIsOnlyWhatGatedSigned covers the resolver: anything else in the
// cookie makes the request anonymous rather than an error.
func TestASessionIsOnlyWhatGatedSigned(t *testing.T) {
	w := newWorld(t)
	now := w.now

	tests := map[string]struct {
		cookie *http.Cookie
		want   string
	}{
		"no cookie at all": {},
		"a session gated signed": {
			cookie: &http.Cookie{Name: SessionCookieName, Value: mustSign(t, Token{
				Kind: KindSession, Subject: "github:octocat", Audience: shopHost,
				IssuedAt: now, ExpiresAt: now.Add(time.Hour),
			})},
			want: "github:octocat",
		},
		"a handoff offered as a session": {
			cookie: &http.Cookie{Name: SessionCookieName, Value: mustSign(t, Token{
				Kind: KindHandoff, Subject: "github:octocat", Audience: shopHost,
				Next: "/", IssuedAt: now, ExpiresAt: now.Add(time.Hour),
			})},
		},
		"a session for another host": {
			cookie: &http.Cookie{Name: SessionCookieName, Value: mustSign(t, Token{
				Kind: KindSession, Subject: "github:octocat", Audience: otherHost,
				IssuedAt: now, ExpiresAt: now.Add(time.Hour),
			})},
		},
		"an expired session": {
			cookie: &http.Cookie{Name: SessionCookieName, Value: mustSign(t, Token{
				Kind: KindSession, Subject: "github:octocat", Audience: shopHost,
				IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
			})},
		},
		"something that is not a token": {
			cookie: &http.Cookie{Name: SessionCookieName, Value: "have a nice day"},
		},
		"an empty cookie": {
			cookie: &http.Cookie{Name: SessionCookieName, Value: ""},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://"+shopHost+"/reports", nil)
			r.Host = shopHost
			if tc.cookie != nil {
				r.AddCookie(tc.cookie)
			}
			if got := w.sessions.Subject(r); got != tc.want {
				t.Errorf("Subject() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestASessionWithoutAKeyIsAnonymous covers the moment before the signing key
// has been read out of its Secret. Nobody is logged in, which is the safe
// answer; the alternative is trusting a cookie nothing verified.
func TestASessionWithoutAKeyIsAnonymous(t *testing.T) {
	valid := mustSign(t, Token{
		Kind: KindSession, Subject: "github:octocat", Audience: shopHost,
		IssuedAt: testTime(), ExpiresAt: testTime().Add(time.Hour),
	})
	sessions := &Sessions{Keys: StaticKey(nil), TTL: time.Hour, Now: testTime}

	r := httptest.NewRequest(http.MethodGet, "https://"+shopHost+"/reports", nil)
	r.Host = shopHost
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: valid})
	if got := sessions.Subject(r); got != "" {
		t.Errorf("Subject() = %q, want nobody", got)
	}
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	return string(body)
}
