package connector

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
	"testing"
	"time"
)

// A fake identity provider, near enough to the real ones to exercise every
// branch of the connectors without leaving the process (ADR 0007).

// fakeGitHub answers the two requests the GitHub connector makes.
type fakeGitHub struct {
	*httptest.Server

	// clientID and clientSecret are what the exchange must present.
	clientID     string
	clientSecret string
	// code is the authorisation code the exchange must present.
	code string
	// accessToken is handed back for that code.
	accessToken string
	// login is what /user answers with.
	login string

	// The knobs the failure cases turn.
	tokenStatus  int
	tokenBody    string
	userStatus   int
	userBody     string
	lastAuthUser string
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	g := &fakeGitHub{
		clientID:     "client-id",
		clientSecret: "client-secret",
		code:         "the-code",
		accessToken:  "gho_token",
		login:        "octocat",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", g.token)
	mux.HandleFunc("/user", g.user)
	g.Server = httptest.NewServer(mux)
	t.Cleanup(g.Close)
	return g
}

func (g *fakeGitHub) token(w http.ResponseWriter, r *http.Request) {
	if g.tokenBody != "" || g.tokenStatus != 0 {
		if g.tokenStatus != 0 {
			w.WriteHeader(g.tokenStatus)
		}
		w.Write([]byte(g.tokenBody))
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("client_id") != g.clientID || r.PostForm.Get("client_secret") != g.clientSecret {
		writeJSON(w, http.StatusOK, map[string]string{"error": "incorrect_client_credentials"})
		return
	}
	if r.PostForm.Get("code") != g.code {
		writeJSON(w, http.StatusOK, map[string]string{"error": "bad_verification_code"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"access_token": g.accessToken, "token_type": "bearer"})
}

func (g *fakeGitHub) user(w http.ResponseWriter, r *http.Request) {
	g.lastAuthUser = r.Header.Get("Authorization")
	if g.userBody != "" || g.userStatus != 0 {
		if g.userStatus != 0 {
			w.WriteHeader(g.userStatus)
		}
		w.Write([]byte(g.userBody))
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+g.accessToken {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "Bad credentials"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"login": g.login, "id": 1})
}

// fakeOIDC answers discovery, the token exchange and the key set.
type fakeOIDC struct {
	*httptest.Server

	key   *rsa.PrivateKey
	keyID string

	clientID     string
	clientSecret string
	code         string

	// claims is what the ID token says. Tests rewrite it in place.
	claims map[string]any
	// signWith, when set, signs the ID token with this key instead.
	signWith *rsa.PrivateKey
	// alg, when set, is written into the header instead of RS256.
	alg string
	// kid, when set, is written into the header instead of keyID.
	kid string
	// issuerOverride, when set, is what discovery claims to be.
	issuerOverride string
	// idToken, when set, is handed back verbatim.
	idToken string
	// tokenStatus, when set, is the status the exchange answers with.
	tokenStatus int

	// exchanges counts the token requests, so a test can see a code being
	// spent more than once.
	exchanges int
}

func newFakeOIDC(t *testing.T) *fakeOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	p := &fakeOIDC{
		key:          key,
		keyID:        "key-1",
		clientID:     "client-id",
		clientSecret: "client-secret",
		code:         "the-code",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/token", p.token)
	mux.HandleFunc("/keys", p.keys)
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {})
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	p.claims = map[string]any{
		"iss":            p.URL,
		"aud":            p.clientID,
		"sub":            "1234567890",
		"email":          "someone@example.com",
		"email_verified": true,
	}
	return p
}

func (p *fakeOIDC) issuer() string {
	if p.issuerOverride != "" {
		return p.issuerOverride
	}
	return p.URL
}

func (p *fakeOIDC) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                 p.issuer(),
		"authorization_endpoint": p.URL + "/authorize",
		"token_endpoint":         p.URL + "/token",
		"jwks_uri":               p.URL + "/keys",
	})
}

func (p *fakeOIDC) keys(w http.ResponseWriter, r *http.Request) {
	pub := p.key.Public().(*rsa.PublicKey)
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": p.keyID,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

func (p *fakeOIDC) token(w http.ResponseWriter, r *http.Request) {
	p.exchanges++
	if p.tokenStatus != 0 {
		http.Error(w, "no", p.tokenStatus)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("client_id") != p.clientID || r.PostForm.Get("client_secret") != p.clientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if r.PostForm.Get("code") != p.code {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": "at",
		"token_type":   "Bearer",
		"id_token":     p.signedIDToken(),
	})
}

// signedIDToken renders the current claims as a JWT.
func (p *fakeOIDC) signedIDToken() string {
	if p.idToken != "" {
		return p.idToken
	}
	claims := map[string]any{}
	for k, v := range p.claims {
		claims[k] = v
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}

	alg := p.alg
	if alg == "" {
		alg = "RS256"
	}
	kid := p.kid
	if kid == "" {
		kid = p.keyID
	}
	header := encodeSegment(map[string]any{"alg": alg, "kid": kid, "typ": "JWT"})
	body := encodeSegment(claims)
	signing := header + "." + body

	if alg == "none" {
		return signing + "."
	}
	key := p.key
	if p.signWith != nil {
		key = p.signWith
	}
	sum := sha256Sum(signing)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum)
	if err != nil {
		panic(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
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

// sha256Sum is what an RS256 signature is computed over.
func sha256Sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}
