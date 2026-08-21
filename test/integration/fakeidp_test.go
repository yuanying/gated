//go:build integration

package integration

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// Fake identity providers: one that speaks GitHub's OAuth flow and one that
// speaks OpenID Connect the way Google does.
//
// They are complete enough to be driven by a browser — the authorize endpoint
// redirects back with a code, and the token endpoint only honours a code it
// issued — because what these tests are about is the round trip, not the
// individual request. Nothing here contacts a real provider (ADR 0007).

// fakeGitHub is an OAuth application's worth of GitHub.
type fakeGitHub struct {
	*httptest.Server

	clientID     string
	clientSecret string
	// login is the account the visitor is signed in to GitHub as.
	login string

	issued map[string]string // code -> access token
}

func startFakeGitHub(t *testing.T, login string) *fakeGitHub {
	t.Helper()
	g := &fakeGitHub{
		clientID:     "github-client-id",
		clientSecret: "github-client-secret",
		login:        login,
		issued:       map[string]string{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != g.clientID {
			http.Error(w, "unknown application", http.StatusBadRequest)
			return
		}
		code := "code-" + randomString(t)
		g.issued[code] = "gho_" + randomString(t)

		back, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		back.RawQuery = url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("client_id") != g.clientID || r.PostForm.Get("client_secret") != g.clientSecret {
			writeJSON(w, http.StatusOK, map[string]string{"error": "incorrect_client_credentials"})
			return
		}
		token, ok := g.issued[r.PostForm.Get("code")]
		if !ok {
			writeJSON(w, http.StatusOK, map[string]string{"error": "bad_verification_code"})
			return
		}
		delete(g.issued, r.PostForm.Get("code"))
		writeJSON(w, http.StatusOK, map[string]string{"access_token": token, "token_type": "bearer"})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "Bad credentials"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"login": g.login, "id": 1})
	})

	g.Server = httptest.NewServer(mux)
	t.Cleanup(g.Close)
	return g
}

// fakeGoogle is an OpenID Connect provider with one signing key.
type fakeGoogle struct {
	*httptest.Server

	clientID     string
	clientSecret string
	key          *rsa.PrivateKey

	// email is the address on the account, and emailVerified is what the
	// provider says about it. The second one is the whole point of these
	// tests (ADR 0003).
	email         string
	emailVerified bool

	issued map[string]string // code -> nonce
}

func startFakeGoogle(t *testing.T, email string, verified bool) *fakeGoogle {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	g := &fakeGoogle{
		clientID:      "google-client-id",
		clientSecret:  "google-client-secret",
		key:           key,
		email:         email,
		emailVerified: verified,
		issued:        map[string]string{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                 g.URL,
			"authorization_endpoint": g.URL + "/authorize",
			"token_endpoint":         g.URL + "/token",
			"jwks_uri":               g.URL + "/keys",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		pub := g.key.Public().(*rsa.PublicKey)
		writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "key-1",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != g.clientID {
			http.Error(w, "unknown client", http.StatusBadRequest)
			return
		}
		code := "code-" + randomString(t)
		g.issued[code] = q.Get("nonce")

		back, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		back.RawQuery = url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("client_id") != g.clientID || r.PostForm.Get("client_secret") != g.clientSecret {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
			return
		}
		nonce, ok := g.issued[r.PostForm.Get("code")]
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		delete(g.issued, r.PostForm.Get("code"))
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "at", "token_type": "Bearer",
			"id_token": g.idToken(nonce),
		})
	})

	g.Server = httptest.NewServer(mux)
	t.Cleanup(g.Close)
	return g
}

// idToken signs the claims the provider would make about this account.
func (g *fakeGoogle) idToken(nonce string) string {
	now := time.Now()
	claims := map[string]any{
		"iss":            g.URL,
		"aud":            g.clientID,
		"sub":            "1234567890",
		"email":          g.email,
		"email_verified": g.emailVerified,
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	signing := encodeSegment(map[string]any{"alg": "RS256", "kid": "key-1", "typ": "JWT"}) +
		"." + encodeSegment(claims)

	sum := sha256.Sum256([]byte(signing))
	signature, err := rsa.SignPKCS1v15(rand.Reader, g.key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func encodeSegment(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func randomString(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("reading randomness: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
