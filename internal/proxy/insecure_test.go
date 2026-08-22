package proxy_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yuanying/gated/internal/proxy"
)

// solverFunc adapts a function to the ChallengeSolver interface.
type solverFunc func(ctx context.Context, host, token string) (string, bool)

func (f solverFunc) KeyAuthorization(ctx context.Context, host, token string) (string, bool) {
	return f(ctx, host, token)
}

// do sends a request to h without a network round trip.
func do(h http.Handler, method, host, target string) *http.Response {
	r := httptest.NewRequest(method, target, nil)
	r.Host = host
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Result()
}

func TestInsecureHandlerRedirectsToHTTPS(t *testing.T) {
	h := &proxy.InsecureHandler{}

	tests := []struct {
		name   string
		method string
		target string
		want   string
	}{
		{"root", http.MethodGet, "/", "https://app.example.com/"},
		{"a path with a query", http.MethodGet, "/a/b?c=d", "https://app.example.com/a/b?c=d"},
		{"a method with a body", http.MethodPost, "/submit", "https://app.example.com/submit"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := do(h, tc.method, "app.example.com", tc.target)
			// 308 rather than 301: a permanent redirect that keeps the
			// method, so a POST is not silently turned into a GET.
			if resp.StatusCode != http.StatusPermanentRedirect {
				t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusPermanentRedirect)
			}
			if got := resp.Header.Get("Location"); got != tc.want {
				t.Errorf("Location = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestInsecureHandlerDropsThePortFromTheRedirect(t *testing.T) {
	// The listen address is an implementation detail of the pod; the name the
	// client used is not.
	resp := do(&proxy.InsecureHandler{}, http.MethodGet, "app.example.com:8080", "/")
	if got := resp.Header.Get("Location"); got != "https://app.example.com/" {
		t.Errorf("Location = %q, want %q", got, "https://app.example.com/")
	}
}

func TestInsecureHandlerRejectsARequestWithoutAHost(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = ""
	w := httptest.NewRecorder()
	(&proxy.InsecureHandler{}).ServeHTTP(w, r)

	if got := w.Result().StatusCode; got != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", got, http.StatusBadRequest)
	}
}

func TestInsecureHandlerAnswersTheACMEChallenge(t *testing.T) {
	h := &proxy.InsecureHandler{
		Solver: solverFunc(func(_ context.Context, host, token string) (string, bool) {
			if host != "app.example.com" || token != "the-token" {
				return "", false
			}
			return "the-token.the-thumbprint", true
		}),
	}

	resp := do(h, http.MethodGet, "app.example.com", "/.well-known/acme-challenge/the-token")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "the-token.the-thumbprint" {
		t.Errorf("body = %q, want %q", body, "the-token.the-thumbprint")
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/plain; charset=utf-8")
	}
}

func TestChallengePathIsNeverRedirectedOrProxied(t *testing.T) {
	// The challenge path belongs to gated, not to any backend (ADR 0005).
	// Without a solver it is a 404 — never a redirect, which would send the
	// validation server to TLS on a host whose certificate does not exist
	// yet, and never a proxied request, which would let a backend answer.
	tests := []struct {
		name   string
		solver proxy.ChallengeSolver
		target string
	}{
		{
			name:   "no solver configured",
			target: "/.well-known/acme-challenge/the-token",
		},
		{
			name:   "an unknown token",
			solver: solverFunc(func(context.Context, string, string) (string, bool) { return "", false }),
			target: "/.well-known/acme-challenge/other-token",
		},
		{
			name:   "no token at all",
			solver: solverFunc(func(context.Context, string, string) (string, bool) { return "keyauth", true }),
			target: "/.well-known/acme-challenge/",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := do(&proxy.InsecureHandler{Solver: tc.solver}, http.MethodGet, "app.example.com", tc.target)
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
			}
			if loc := resp.Header.Get("Location"); loc != "" {
				t.Errorf("Location = %q, want none", loc)
			}
		})
	}
}

func TestChallengePathIsMatchedExactly(t *testing.T) {
	// A path that merely starts with the same letters is ordinary traffic.
	resp := do(&proxy.InsecureHandler{}, http.MethodGet, "app.example.com", "/.well-known/acme-challenges")
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("status = %d, want a redirect", resp.StatusCode)
	}
}

// hostSet answers for a fixed set of names, standing in for the routing table
// the plain listener consults.
type hostSet map[string]bool

func (s hostSet) HasHost(host string) bool { return s[host] }

func TestInsecureHandlerRedirectsOnlyHostsItRoutes(t *testing.T) {
	// Redirecting a name gated has no route for tells a scanner that
	// something answers here, and then answers 404 on the other side
	// anyway. With a set of hosts to consult, the 404 comes first.
	h := &proxy.InsecureHandler{Hosts: hostSet{"app.example.com": true}}

	if resp := do(h, http.MethodGet, "app.example.com", "/a"); resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("a routed host: status = %d, want %d", resp.StatusCode, http.StatusPermanentRedirect)
	}
	resp := do(h, http.MethodGet, "nobody.example.org", "/a")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("an unrouted host: status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	if got := resp.Header.Get("Location"); got != "" {
		t.Errorf("an unrouted host: Location = %q, want no redirect", got)
	}
}

func TestInsecureHandlerRedirectsEveryHostWithoutASet(t *testing.T) {
	// A handler with no set of hosts to consult keeps redirecting
	// everything, which is what it has always done and what the tests above
	// this one describe.
	resp := do(&proxy.InsecureHandler{}, http.MethodGet, "nobody.example.org", "/a")
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusPermanentRedirect)
	}
}

func TestInsecureHandlerAnswersChallengesForAnyHost(t *testing.T) {
	// The validation server reaches whichever replica the load balancer
	// hands it, and asks for a name that may have no route yet — a
	// certificate is ordered before the Ingress it belongs to serves
	// anything. Answering a challenge therefore cannot depend on the
	// routing table (ADR 0015).
	h := &proxy.InsecureHandler{
		Hosts: hostSet{"app.example.com": true},
		Solver: solverFunc(func(_ context.Context, host, token string) (string, bool) {
			return "key-auth-for-" + host + "-" + token, true
		}),
	}

	resp := do(h, http.MethodGet, "brand-new.example.org", proxy.ChallengePath+"token")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, _ := io.ReadAll(resp.Body)
	if want := "key-auth-for-brand-new.example.org-token"; string(body) != want {
		t.Errorf("body = %q, want %q", body, want)
	}
}
