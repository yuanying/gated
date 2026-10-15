package assertion_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/yuanying/gated/internal/assertion"
	"github.com/yuanying/gated/internal/assertion/assertiontest"
)

// What a backend relies on is fixed by ADR 0034: a JWS in compact form, signed
// with Ed25519 only, naming who gated authenticated for which host, good for a
// minute. These tests read the assertion the way a backend would — through the
// published key set and nothing else — so that what is checked is the wire
// form, not this package's opinion of it.

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	return key
}

func privatePEM(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("encoding a private key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func publicPEM(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("encoding a public key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func keySet(t *testing.T, data map[string][]byte) *assertion.KeySet {
	t.Helper()
	keys, err := assertion.ParseKeySet(data)
	if err != nil {
		t.Fatalf("ParseKeySet() = %v", err)
	}
	return keys
}

func jwks(t *testing.T, keys *assertion.KeySet) []byte {
	t.Helper()
	doc, err := keys.JWKS()
	if err != nil {
		t.Fatalf("JWKS() = %v", err)
	}
	return doc
}

var (
	issuedAt = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	claims   = assertion.Claims{
		Issuer:   "https://auth.example.com",
		Subject:  "github:octocat",
		Audience: "shop.example.com",
		IssuedAt: issuedAt,
	}
	expect = assertiontest.Expect{
		Issuer:   "https://auth.example.com",
		Audience: "shop.example.com",
		Now:      issuedAt.Add(time.Second),
	}
)

func TestAnAssertionVerifiesAgainstThePublishedKeys(t *testing.T) {
	keys := keySet(t, map[string][]byte{assertion.SigningKeyEntry: privatePEM(t, newKey(t))})

	signed, err := keys.Sign(claims)
	if err != nil {
		t.Fatalf("Sign() = %v", err)
	}

	got, err := assertiontest.Verify(jwks(t, keys), signed, expect)
	if err != nil {
		t.Fatalf("a backend could not verify what gated signed: %v", err)
	}
	if got.Subject != "github:octocat" {
		t.Errorf("sub = %q, want github:octocat", got.Subject)
	}
	if !got.IssuedAt.Equal(issuedAt) {
		t.Errorf("iat = %v, want %v", got.IssuedAt, issuedAt)
	}
	if want := issuedAt.Add(time.Minute); !got.ExpiresAt.Equal(want) {
		t.Errorf("exp = %v, want %v: an assertion is good for sixty seconds", got.ExpiresAt, want)
	}
}

// The header and the claims are the closed set the ADR lists. Anything more
// is something a backend might start to rely on.
func TestTheWireFormIsWhatTheADRSays(t *testing.T) {
	key := newKey(t)
	keys := keySet(t, map[string][]byte{assertion.SigningKeyEntry: privatePEM(t, key)})

	signed, err := keys.Sign(assertion.Claims{
		Issuer:   "https://auth.example.com",
		Subject:  "github:octocat",
		Audience: "Shop.Example.COM:8443",
		IssuedAt: issuedAt,
	})
	if err != nil {
		t.Fatalf("Sign() = %v", err)
	}

	parts := strings.Split(signed, ".")
	if len(parts) != 3 {
		t.Fatalf("%q is not a JWS in compact form", signed)
	}

	var header map[string]any
	decodeSegment(t, parts[0], &header)
	wantHeader := map[string]any{
		"alg": "EdDSA",
		"typ": "gated-assertion+jwt",
		"kid": thumbprint(key.Public().(ed25519.PublicKey)),
	}
	assertSameJSON(t, "header", header, wantHeader)

	var body map[string]any
	decodeSegment(t, parts[1], &body)
	wantBody := map[string]any{
		"iss": "https://auth.example.com",
		"sub": "github:octocat",
		// Lower case and without the port, whatever the request said.
		"aud": "shop.example.com",
		"iat": float64(issuedAt.Unix()),
		"exp": float64(issuedAt.Add(time.Minute).Unix()),
	}
	assertSameJSON(t, "claims", body, wantBody)

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("the signature is not base64url: %v", err)
	}
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), []byte(parts[0]+"."+parts[1]), signature) {
		t.Error("the signature is not an Ed25519 signature over the first two segments")
	}
}

// The key identifier is the RFC 7638 thumbprint, so that a backend, an
// operator and gated all arrive at the same name for the same key.
func TestTheKeyIDIsTheJWKThumbprint(t *testing.T) {
	// RFC 8037 appendix A.3.
	x, err := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if err != nil {
		t.Fatal(err)
	}
	const want = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
	if got := assertion.KeyID(ed25519.PublicKey(x)); got != want {
		t.Errorf("KeyID() = %q, want %q", got, want)
	}
}

// A backend that holds only the key set can verify against it; one that is
// handed an assertion it was not meant to accept refuses it. The verifier is
// the eight steps of ADR 0034, so each row is one of them failing.
func TestWhatABackendRefuses(t *testing.T) {
	key := newKey(t)
	keys := keySet(t, map[string][]byte{assertion.SigningKeyEntry: privatePEM(t, key)})
	signed, err := keys.Sign(claims)
	if err != nil {
		t.Fatalf("Sign() = %v", err)
	}
	other := keySet(t, map[string][]byte{assertion.SigningKeyEntry: privatePEM(t, newKey(t))})

	tests := map[string]struct {
		jwks   []byte
		token  string
		expect assertiontest.Expect
	}{
		"nothing": {jwks: jwks(t, keys), token: "", expect: expect},
		"a key set that does not hold the key": {
			jwks: jwks(t, other), token: signed, expect: expect,
		},
		"a different issuer": {
			jwks: jwks(t, keys), token: signed,
			expect: assertiontest.Expect{Issuer: "https://login.example.org", Audience: expect.Audience, Now: expect.Now},
		},
		"a different host": {
			jwks: jwks(t, keys), token: signed,
			expect: assertiontest.Expect{Issuer: expect.Issuer, Audience: "admin.example.com", Now: expect.Now},
		},
		"a minute later": {
			jwks: jwks(t, keys), token: signed,
			expect: assertiontest.Expect{Issuer: expect.Issuer, Audience: expect.Audience, Now: issuedAt.Add(time.Minute)},
		},
		"issued well in the future": {
			jwks: jwks(t, keys), token: signed,
			expect: assertiontest.Expect{Issuer: expect.Issuer, Audience: expect.Audience, Now: issuedAt.Add(-5 * time.Minute)},
		},
		"another subject written over the claims": {
			jwks: jwks(t, keys), token: replaceSegment(t, signed, 1, map[string]any{
				"iss": "https://auth.example.com", "sub": "github:admin", "aud": "shop.example.com",
				"iat": issuedAt.Unix(), "exp": issuedAt.Add(time.Minute).Unix(),
			}),
			expect: expect,
		},
		"alg none": {
			jwks: jwks(t, keys), token: replaceSegment(t, signed, 0, map[string]any{
				"alg": "none", "typ": "gated-assertion+jwt", "kid": assertion.KeyID(key.Public().(ed25519.PublicKey)),
			}),
			expect: expect,
		},
		"another type of JWT": {
			jwks: jwks(t, keys), token: replaceSegment(t, signed, 0, map[string]any{
				"alg": "EdDSA", "typ": "JWT", "kid": assertion.KeyID(key.Public().(ed25519.PublicKey)),
			}),
			expect: expect,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got, err := assertiontest.Verify(tc.jwks, tc.token, tc.expect); err == nil {
				t.Errorf("Verify() = %+v, nil; want a refusal", got)
			}
		})
	}
}

// A key published ahead of being used for signing is how a rotation keeps
// every request verifiable (ADR 0034). Both halves are checked: the published
// key is in the set, and nothing signs with it.
func TestPublishedKeysAreInTheSetButNeverSign(t *testing.T) {
	current, next, retired := newKey(t), newKey(t), newKey(t)

	keys := keySet(t, map[string][]byte{
		assertion.SigningKeyEntry: privatePEM(t, current),
		// Either half of a key pair may be put here: the private key
		// that was signing until a moment ago, or the public key of the
		// one about to.
		assertion.PublishedKeysEntry: append(publicPEM(t, next), privatePEM(t, retired)...),
	})

	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(jwks(t, keys), &set); err != nil {
		t.Fatalf("the key set is not JSON: %v", err)
	}
	var ids []string
	for _, k := range set.Keys {
		ids = append(ids, k["kid"].(string))
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
			if _, ok := k[private]; ok {
				t.Errorf("the published key %v carries %q, which is private", k["kid"], private)
			}
		}
		want := map[string]any{
			"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
			"kid": k["kid"], "x": k["x"],
		}
		assertSameJSON(t, "published key", k, want)
	}
	wantIDs := []string{
		assertion.KeyID(current.Public().(ed25519.PublicKey)),
		assertion.KeyID(next.Public().(ed25519.PublicKey)),
		assertion.KeyID(retired.Public().(ed25519.PublicKey)),
	}
	if strings.Join(ids, ",") != strings.Join(wantIDs, ",") {
		t.Errorf("the key set holds %v, want %v (the signing key first)", ids, wantIDs)
	}

	signed, err := keys.Sign(claims)
	if err != nil {
		t.Fatalf("Sign() = %v", err)
	}
	only := keySet(t, map[string][]byte{assertion.SigningKeyEntry: privatePEM(t, current)})
	if _, err := assertiontest.Verify(jwks(t, only), signed, expect); err != nil {
		t.Errorf("the assertion was not signed by the signing key: %v", err)
	}
}

// The signing key appearing among the published ones as well is what an
// operator midway through a rotation might well write. It is published once.
func TestAKeyListedTwiceIsPublishedOnce(t *testing.T) {
	key := newKey(t)
	keys := keySet(t, map[string][]byte{
		assertion.SigningKeyEntry:    privatePEM(t, key),
		assertion.PublishedKeysEntry: publicPEM(t, key),
	})
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(jwks(t, keys), &set); err != nil {
		t.Fatalf("the key set is not JSON: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Errorf("the key set holds %d keys, want 1", len(set.Keys))
	}
}

// A Secret that cannot be signed with is refused whole, rather than read as
// far as it goes. Half a key set is a rotation that silently lost a key.
func TestASecretThatCannotBeSignedWithIsRefused(t *testing.T) {
	ecdsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not DER at all")})

	tests := map[string]map[string][]byte{
		"empty":                    {},
		"no signing key":           {assertion.PublishedKeysEntry: publicPEM(t, newKey(t))},
		"a signing key not in PEM": {assertion.SigningKeyEntry: []byte("0123456789abcdef0123456789abcdef")},
		"a public key to sign with": {
			assertion.SigningKeyEntry: publicPEM(t, newKey(t)),
		},
		"two signing keys": {
			assertion.SigningKeyEntry: append(privatePEM(t, newKey(t)), privatePEM(t, newKey(t))...),
		},
		"a signing key that does not parse": {assertion.SigningKeyEntry: ecdsaPEM},
		"a published key that does not parse": {
			assertion.SigningKeyEntry:    privatePEM(t, newKey(t)),
			assertion.PublishedKeysEntry: ecdsaPEM,
		},
		"text that is not PEM among the published keys": {
			assertion.SigningKeyEntry:    privatePEM(t, newKey(t)),
			assertion.PublishedKeysEntry: append(publicPEM(t, newKey(t)), []byte("left over\n")...),
		},
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if keys, err := assertion.ParseKeySet(data); err == nil {
				t.Errorf("ParseKeySet() = %v, nil; want an error", keys)
			}
		})
	}
}

// What the leader writes into a Secret that is not there is something the
// key set reads back.
func TestAGeneratedSigningKeyIsReadable(t *testing.T) {
	data, err := assertion.GenerateSecretData()
	if err != nil {
		t.Fatalf("GenerateSecretData() = %v", err)
	}
	if _, ok := data[assertion.PublishedKeysEntry]; ok {
		t.Error("a fresh Secret publishes a key nobody asked for")
	}
	keys := keySet(t, data)
	if _, err := keys.Sign(claims); err != nil {
		t.Errorf("a generated key cannot sign: %v", err)
	}

	again, err := assertion.GenerateSecretData()
	if err != nil {
		t.Fatalf("GenerateSecretData() = %v", err)
	}
	if string(again[assertion.SigningKeyEntry]) == string(data[assertion.SigningKeyEntry]) {
		t.Error("two generated keys are the same")
	}
}

// Sign refuses what a backend would have to refuse, so that the mistake shows
// up where the assertion is made.
func TestSignRefusesAnIncompleteAssertion(t *testing.T) {
	keys := keySet(t, map[string][]byte{assertion.SigningKeyEntry: privatePEM(t, newKey(t))})
	tests := map[string]assertion.Claims{
		"no issuer":   {Subject: "github:octocat", Audience: "shop.example.com", IssuedAt: issuedAt},
		"no subject":  {Issuer: "https://auth.example.com", Audience: "shop.example.com", IssuedAt: issuedAt},
		"no audience": {Issuer: "https://auth.example.com", Subject: "github:octocat", IssuedAt: issuedAt},
		"no time":     {Issuer: "https://auth.example.com", Subject: "github:octocat", Audience: "shop.example.com"},
	}
	for name, c := range tests {
		t.Run(name, func(t *testing.T) {
			if signed, err := keys.Sign(c); err == nil {
				t.Errorf("Sign() = %q, nil; want an error", signed)
			}
		})
	}
	var nothing *assertion.KeySet
	if signed, err := nothing.Sign(claims); err == nil {
		t.Errorf("Sign() with no keys = %q, nil; want an error", signed)
	}
}

func TestTheIssuerIsTheOriginOfTheCentralHost(t *testing.T) {
	tests := map[string]string{
		"auth.example.com":       "https://auth.example.com",
		"Auth.Example.com.":      "https://auth.example.com",
		"auth.example.com:8443":  "https://auth.example.com:8443",
		"AUTH.example.com.:8443": "https://auth.example.com:8443",
	}
	for host, want := range tests {
		if got := assertion.Issuer(host); got != want {
			t.Errorf("Issuer(%q) = %q, want %q", host, got, want)
		}
	}
}

func decodeSegment(t *testing.T, segment string, into any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("%q is not base64url: %v", segment, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("%s is not JSON: %v", raw, err)
	}
}

func replaceSegment(t *testing.T, signed string, index int, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(signed, ".")
	parts[index] = base64.RawURLEncoding.EncodeToString(raw)
	return strings.Join(parts, ".")
}

func assertSameJSON(t *testing.T, what string, got, want map[string]any) {
	t.Helper()
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("the %s is\n  %s\nwant\n  %s", what, gotJSON, wantJSON)
	}
}

// thumbprint is RFC 7638 written out by hand, so that the test does not take
// the package's word for it.
func thumbprint(key ed25519.PublicKey) string {
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(key) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
