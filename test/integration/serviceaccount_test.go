//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yuanying/gated/internal/accesstoken"
	"github.com/yuanying/gated/internal/assertion"
	"github.com/yuanying/gated/internal/assertion/assertiontest"
	"github.com/yuanying/gated/internal/authz"
	"github.com/yuanying/gated/internal/proxy"
	"github.com/yuanying/gated/internal/routing"
	"github.com/yuanying/gated/internal/serviceaccount"
)

// A ServiceAccount token on its way through the request path, from the
// Authorization header to what the backend is handed (ADR 0039).
//
// Everything is the code that runs in production — the two token doors, the
// authorisation decision, the proxy and the assertion signer — except the API
// server, whose answers are a table. That the real one answers the way the
// table does is the envtest suite's business; that it is asked at all is the
// end-to-end suite's.

const (
	saAudience  = "https://auth.example.com"
	apiHost     = "api.example.com"
	openAPIHost = "open-api.example.com"
	allowedSA   = "system:serviceaccount:natsumi:assistant"
	otherSA     = "system:serviceaccount:natsumi:somebody-else"
	tokenUser   = "github:robot"
	accessToken = accesstoken.Prefix + "robot"
)

// fakeAPIServer answers TokenReviews from a table.
type fakeAPIServer map[string]serviceaccount.Review

func (f fakeAPIServer) Review(_ context.Context, token, audience string) (serviceaccount.Review, error) {
	review := f[token]
	if audience != saAudience {
		return serviceaccount.Review{}, nil
	}
	return review, nil
}

// serviceAccountToken is shaped the way the API server shapes one. Its
// signature is nothing: only the API server checks it.
func serviceAccountToken(t *testing.T, audience, name string) string {
	t.Helper()
	segment := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return segment(map[string]string{"alg": "RS256"}) + "." +
		segment(map[string]any{"aud": []string{audience}, "exp": time.Now().Add(time.Hour).Unix(), "sub": name}) +
		"." + base64.RawURLEncoding.EncodeToString([]byte("signature"))
}

// arrived is what the backend was handed.
type arrived struct {
	authorization string
	assertion     string
}

func TestAServiceAccountIsAuthorisedLikeAnybodyElse(t *testing.T) {
	var got *arrived
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = &arrived{authorization: r.Header.Get("Authorization"), assertion: r.Header.Get("Gated-Assertion")}
	}))
	t.Cleanup(backend.Close)

	tables := &proxy.TableStore{}
	tables.Store(routing.BuildTable([]routing.Ingress{
		ingressFor("natsumi", "api", apiHost),
		ingressFor("fraction", "open", openAPIHost),
	}))
	policies := &proxy.PolicyStore{}
	policies.Store(authz.BuildPolicySet(
		[]authz.Role{roleFor("natsumi", "api")},
		// The subject is written the way RBAC writes it.
		[]authz.Binding{{Namespace: "natsumi", RoleName: "api", Subjects: []string{allowedSA, tokenUser}}},
	))

	allowed := serviceAccountToken(t, saAudience, "assistant")
	other := serviceAccountToken(t, saAudience, "somebody-else")
	forged := serviceAccountToken(t, saAudience, "forged")
	elsewhere := serviceAccountToken(t, "a2a", "assistant")
	apiServer := fakeAPIServer{
		allowed: {Authenticated: true, Username: allowedSA, Audiences: []string{saAudience}},
		other:   {Authenticated: true, Username: otherSA, Audiences: []string{saAudience}},
		forged:  {Authenticated: false, Error: "invalid bearer token"},
	}

	tokens := &accesstoken.Store{}
	tokens.Store(accesstoken.NewSnapshot([]accesstoken.Entry{{
		Identity: accesstoken.Identity{Subject: tokenUser, Namespace: "natsumi", Name: "robot"},
		Hash:     accesstoken.Hash(accessToken),
	}}))
	accessTokens := &accesstoken.Authenticator{Tokens: tokens}
	serviceAccounts := &serviceaccount.Authenticator{Audience: saAudience, Reviewer: apiServer}

	data, err := assertion.GenerateSecretData()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := assertion.ParseKeySet(data)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := keys.JWKS()
	if err != nil {
		t.Fatal(err)
	}

	decision := &proxy.Authorization{
		Policies: policies,
		Subjects: proxy.SubjectResolvers{accessTokens, serviceAccounts},
		AuthHost: authHost,
	}
	server := httptest.NewServer(&proxy.Handler{
		Tables:   tables,
		Backends: staticBackend(backend.Listener.Addr().String()),
		Assertions: &assertion.Signer{
			Keys:   assertion.StaticKeys{Set: keys},
			Issuer: assertion.Issuer(authHost),
		},
		Middleware: func(next http.Handler) http.Handler {
			return accessTokens.Wrap(serviceAccounts.Wrap(decision.Wrap(next)))
		},
	})
	t.Cleanup(server.Close)

	send := func(t *testing.T, host, token string) int {
		t.Helper()
		got = nil
		req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/things", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	t.Run("a bound ServiceAccount reaches the backend, vouched for and without its token", func(t *testing.T) {
		if status := send(t, apiHost, allowed); status != http.StatusOK || got == nil {
			t.Fatalf("answered %d, want 200 from the backend", status)
		}
		if got.authorization != "" {
			t.Errorf("the backend was handed Authorization %q", got.authorization)
		}
		claims, err := assertiontest.Verify(jwks, got.assertion, assertiontest.Expect{
			Issuer:   assertion.Issuer(authHost),
			Audience: apiHost,
			Now:      time.Now(),
		})
		if err != nil {
			t.Fatalf("the assertion does not verify: %v", err)
		}
		if claims.Subject != allowedSA {
			t.Errorf("the assertion vouches for %q, want %q", claims.Subject, allowedSA)
		}
	})

	t.Run("a ServiceAccount nothing grants to is refused", func(t *testing.T) {
		if status := send(t, apiHost, other); status != http.StatusForbidden {
			t.Errorf("answered %d, want 403", status)
		}
	})

	t.Run("a forged token is nobody", func(t *testing.T) {
		if status := send(t, apiHost, forged); status != http.StatusUnauthorized {
			t.Errorf("answered %d, want 401", status)
		}
	})

	t.Run("a token for somebody else is nobody", func(t *testing.T) {
		if status := send(t, apiHost, elsewhere); status != http.StatusUnauthorized {
			t.Errorf("answered %d, want 401", status)
		}
	})

	t.Run("a token for somebody else reaches them as it came", func(t *testing.T) {
		// The token fraction-agents checks for itself, on a host
		// nothing protects: gated did not spend it, so it is not
		// gated's to take away.
		if status := send(t, openAPIHost, elsewhere); status != http.StatusOK || got == nil {
			t.Fatalf("answered %d, want 200 from the backend", status)
		}
		if got.authorization != "Bearer "+elsewhere {
			t.Errorf("the backend was handed Authorization %q, want the token as it came", got.authorization)
		}
		if got.assertion != "" {
			t.Error("a request nobody was authenticated for carried an assertion")
		}
	})

	t.Run("an AccessToken still opens its own door", func(t *testing.T) {
		if status := send(t, apiHost, accessToken); status != http.StatusOK || got == nil {
			t.Fatalf("answered %d, want 200 from the backend", status)
		}
		if got.authorization != "" {
			t.Errorf("the backend was handed Authorization %q", got.authorization)
		}
	})
}
