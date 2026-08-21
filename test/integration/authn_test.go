//go:build integration

package integration

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yuanying/gated/internal/authn"
	"github.com/yuanying/gated/internal/authn/connector"
	"github.com/yuanying/gated/internal/authz"
	"github.com/yuanying/gated/internal/proxy"
	"github.com/yuanying/gated/internal/routing"
)

// The login as a visitor experiences it: an unauthenticated request to a
// protected host, a round trip through an identity provider, and the same
// request answered — or refused, when the provider will not vouch for the
// address it named.
//
// Everything but the identity provider is the code that runs in production:
// the real connectors, the real central authentication host, the real
// authorisation middleware and the real proxy. The provider is a fake, and no
// test in this repository contacts a real one (ADR 0007).

const (
	authHost   = "auth.example.com"
	shopHost   = "shop.example.com"
	wikiHost   = "wiki.example.com"
	sessionKey = "0123456789abcdef0123456789abcdef"
)

// gated is one process's worth of the request path.
type gated struct {
	server  *httptest.Server
	backend *httptest.Server
	client  *http.Client
}

// start builds the request path around a set of identity providers, protecting
// the two hosts below and granting them to one subject.
func start(t *testing.T, subject string, connectors ...connector.Connector) *gated {
	t.Helper()

	// Reaching the backend at all is the assertion: nothing here is granted
	// to system:unauthenticated, so a response from it means a subject the
	// binding names was established.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "served "+r.URL.Path)
	}))
	t.Cleanup(backend.Close)

	tables := &proxy.TableStore{}
	tables.Store(routing.BuildTable([]routing.Ingress{
		ingressFor("shop", "storefront", shopHost),
		ingressFor("wiki", "notes", wikiHost),
		ingressFor("gated-system", "login", authHost),
	}))

	policies := &proxy.PolicyStore{}
	policies.Store(authz.BuildPolicySet(
		[]authz.Role{
			roleFor("shop", "storefront"),
			roleFor("wiki", "notes"),
		},
		[]authz.Binding{
			{Namespace: "shop", RoleName: "storefront", Subjects: []string{subject}},
			{Namespace: "wiki", RoleName: "notes", Subjects: []string{subject}},
		},
	))

	keys := authn.StaticKey(sessionKey)
	sessions := &authn.Sessions{Keys: keys, TTL: time.Hour}
	protected := &authn.Protected{Keys: keys, Sessions: sessions}
	central := &authn.AuthHost{
		Host:       authHost,
		Keys:       keys,
		Connectors: connector.NewSet(connectors...),
		Hosts:      tables,
	}

	handler := &authn.Router{
		AuthHost: authHost,
		Central:  central,
		Callback: protected,
		Next: &proxy.Handler{
			Tables:   tables,
			Backends: staticBackend(backend.Listener.Addr().String()),
			Middleware: (&proxy.Authorization{
				Policies:     policies,
				Subjects:     sessions,
				AuthHost:     authHost,
				LoginBinding: protected.StartLogin,
			}).Wrap,
		},
	}

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("building a cookie jar: %v", err)
	}
	return &gated{
		server:  server,
		backend: backend,
		client: &http.Client{
			Jar: jar,
			Transport: &virtualHosts{
				addr:  server.Listener.Addr().String(),
				hosts: map[string]bool{authHost: true, shopHost: true, wikiHost: true},
			},
		},
	}
}

// browse makes a request the way a browser would: as https, asking for HTML,
// following redirects, keeping cookies.
//
// The Accept header is what decides whether a refusal is a login or a
// challenge (ADR 0018), so a test that means to be a browser has to say so.
func (g *gated) browse(t *testing.T, host, path string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := g.client.Do(request)
	if err != nil {
		t.Fatalf("GET https://%s%s: %v", host, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// body reads a response.
func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	return string(b)
}

// subject reads the session cookie the browser holds for a host and returns
// who it says the visitor is, which is the only thing in it (ADR 0003).
func (g *gated) subject(t *testing.T, host string) string {
	t.Helper()
	cookie := g.session(t, host)
	if cookie == nil {
		return ""
	}
	token, err := authn.Verify([]byte(sessionKey), cookie.Value, authn.Expect{
		Kind: authn.KindSession, Audience: host, Now: time.Now(),
	})
	if err != nil {
		t.Fatalf("the session cookie for %s does not verify: %v", host, err)
	}
	return token.Subject
}

// session returns the session cookie the jar holds for a host, if any.
func (g *gated) session(t *testing.T, host string) *http.Cookie {
	t.Helper()
	u, err := url.Parse("https://" + host + "/")
	if err != nil {
		t.Fatalf("parsing the host: %v", err)
	}
	for _, c := range g.client.Jar.Cookies(u) {
		if c.Name == authn.SessionCookieName {
			return c
		}
	}
	return nil
}

// TestAGitHubLoginReachesTheBackend is goal 2 of the task for the GitHub
// route: an unauthenticated visitor is taken through the provider and comes
// back as somebody the binding names.
func TestAGitHubLoginReachesTheBackend(t *testing.T) {
	idp := startFakeGitHub(t, "octocat")
	g := start(t, "github:octocat", &connector.GitHub{
		ClientID:     idp.clientID,
		ClientSecret: connector.StaticSecret(idp.clientSecret),
		BaseURL:      idp.URL,
		APIURL:       idp.URL,
	})

	resp := g.browse(t, shopHost, "/reports")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, body(t, resp))
	}
	if got, want := body(t, resp), "served /reports"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if got, want := g.subject(t, shopHost), "github:octocat"; got != want {
		t.Errorf("the session names %q, want %q", got, want)
	}
	if g.session(t, wikiHost) != nil {
		t.Error("a session cookie was left on a host that was never visited (ADR 0003)")
	}
}

// TestAGoogleLoginReachesTheBackend is the same for the OpenID Connect route.
func TestAGoogleLoginReachesTheBackend(t *testing.T) {
	idp := startFakeGoogle(t, "someone@example.com", true)
	g := start(t, "google:someone@example.com", &connector.Google{
		ClientID:     idp.clientID,
		ClientSecret: connector.StaticSecret(idp.clientSecret),
		Issuer:       idp.URL,
	})

	resp := g.browse(t, shopHost, "/reports")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, body(t, resp))
	}
	if got, want := body(t, resp), "served /reports"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if got, want := g.subject(t, shopHost), "google:someone@example.com"; got != want {
		t.Errorf("the session names %q, want %q", got, want)
	}
}

// TestAnUnverifiedAddressIsRefused is the case ADR 0003 names on its own. The
// provider will not say it verified the address, so it says nothing about who
// this is, and the login must not complete.
func TestAnUnverifiedAddressIsRefused(t *testing.T) {
	idp := startFakeGoogle(t, "someone@example.com", false)
	g := start(t, "google:someone@example.com", &connector.Google{
		ClientID:     idp.clientID,
		ClientSecret: connector.StaticSecret(idp.clientSecret),
		Issuer:       idp.URL,
	})

	resp := g.browse(t, shopHost, "/reports")
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("the login completed with an address nobody verified; body: %s", body(t, resp))
	}
	if strings.Contains(body(t, resp), "served") {
		t.Error("the backend was reached")
	}
	if g.session(t, shopHost) != nil {
		t.Error("a session cookie was issued for an address nobody verified")
	}

	// And the resource is still closed, rather than closed only once.
	again := g.browse(t, shopHost, "/reports")
	if again.StatusCode == http.StatusOK {
		t.Errorf("the resource opened on a second attempt; body: %s", body(t, again))
	}
}

// TestASessionDoesNotTravelBetweenHosts checks the scope of what a completed
// login produces: the second host has to be logged in to separately, and the
// cookie for the first is never sent to it (ADR 0003).
func TestASessionDoesNotTravelBetweenHosts(t *testing.T) {
	idp := startFakeGitHub(t, "octocat")
	g := start(t, "github:octocat", &connector.GitHub{
		ClientID:     idp.clientID,
		ClientSecret: connector.StaticSecret(idp.clientSecret),
		BaseURL:      idp.URL,
		APIURL:       idp.URL,
	})

	if resp := g.browse(t, shopHost, "/reports"); resp.StatusCode != http.StatusOK {
		t.Fatalf("the first login: status = %d; body: %s", resp.StatusCode, body(t, resp))
	}
	first := g.session(t, shopHost)

	resp := g.browse(t, wikiHost, "/notes")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the second host: status = %d; body: %s", resp.StatusCode, body(t, resp))
	}
	second := g.session(t, wikiHost)
	if second == nil {
		t.Fatal("the second host issued no session of its own")
	}
	if first != nil && first.Value == second.Value {
		t.Error("the same session was used on two hosts")
	}
}

// TestAProviderThatRefusesLeavesTheResourceClosed covers the visitor being
// turned away at the provider, which is what a login attempt by somebody
// without an account looks like.
func TestAProviderThatRefusesLeavesTheResourceClosed(t *testing.T) {
	idp := startFakeGitHub(t, "octocat")
	g := start(t, "github:octocat", &connector.GitHub{
		ClientID: idp.clientID,
		// The wrong secret: the provider will not complete the exchange.
		ClientSecret: connector.StaticSecret("not the secret"),
		BaseURL:      idp.URL,
		APIURL:       idp.URL,
	})

	resp := g.browse(t, shopHost, "/reports")
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("the login completed anyway; body: %s", body(t, resp))
	}
	if g.session(t, shopHost) != nil {
		t.Error("a session cookie was issued for a login that never completed")
	}
}

// TestSomebodyElsesAccountIsRefused is the other half of the round trip: the
// login completes, and the subject it establishes is not one any binding
// names, so the answer is a refusal rather than a second login.
func TestSomebodyElsesAccountIsRefused(t *testing.T) {
	idp := startFakeGitHub(t, "somebody-else")
	g := start(t, "github:octocat", &connector.GitHub{
		ClientID:     idp.clientID,
		ClientSecret: connector.StaticSecret(idp.clientSecret),
		BaseURL:      idp.URL,
		APIURL:       idp.URL,
	})

	resp := g.browse(t, shopHost, "/reports")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusForbidden, body(t, resp))
	}
	if g.session(t, shopHost) == nil {
		t.Error("the visitor is logged in as somebody, so a session should exist even though they may not pass")
	}
}

// TestALoginIsNotOfferedToAProgram keeps the redirect for browsers. A client
// that did not ask for HTML gets a challenge it can act on (ADR 0018).
func TestALoginIsNotOfferedToAProgram(t *testing.T) {
	idp := startFakeGitHub(t, "octocat")
	g := start(t, "github:octocat", &connector.GitHub{
		ClientID:     idp.clientID,
		ClientSecret: connector.StaticSecret(idp.clientSecret),
		BaseURL:      idp.URL,
		APIURL:       idp.URL,
	})

	request, err := http.NewRequest(http.MethodGet, "https://"+shopHost+"/reports", nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	request.Header.Set("Accept", "*/*")
	resp, err := g.client.Do(request)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
		t.Errorf("WWW-Authenticate = %q, want a Basic challenge", got)
	}
}

// virtualHosts sends the hosts gated answers for to the one server running it,
// leaving the Host header alone, and lets everything else — the identity
// providers — go where it says.
type virtualHosts struct {
	addr  string
	hosts map[string]bool
}

func (v *virtualHosts) RoundTrip(r *http.Request) (*http.Response, error) {
	if !v.hosts[r.URL.Hostname()] {
		return http.DefaultTransport.RoundTrip(r)
	}
	clone := r.Clone(r.Context())
	clone.Host = r.URL.Host
	clone.URL.Scheme = "http"
	clone.URL.Host = v.addr
	return http.DefaultTransport.RoundTrip(clone)
}

// staticBackend forwards everything to one address.
type staticBackend string

func (s staticBackend) Resolve(context.Context, routing.Backend) (string, error) {
	return string(s), nil
}

func ingressFor(namespace, name, host string) routing.Ingress {
	return routing.Ingress{
		Namespace: namespace,
		Name:      name,
		Rules: []routing.HostRule{{
			Host: host,
			Paths: []routing.PathRule{{
				Path:     "/",
				PathType: routing.PathTypePrefix,
				Backend:  routing.Backend{Namespace: namespace, Service: name, PortNumber: 80},
			}},
		}},
	}
}

func roleFor(namespace, name string) authz.Role {
	return authz.Role{
		Namespace: namespace,
		Name:      name,
		Target:    authz.ResourceRef{Namespace: namespace, Name: name},
		Rules:     []authz.Rule{{Paths: []string{"*"}, Methods: []string{"*"}}},
	}
}
