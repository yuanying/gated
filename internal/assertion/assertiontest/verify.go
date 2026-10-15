// Package assertiontest checks a gated assertion the way a backend is told to
// in ADR 0034, so that gated's own tests can read what it signs from the far
// side.
//
// It is written apart from the signing code, against the wire form alone, and
// is not used by gated itself: gated signs and never verifies. Steps 1 to 7 of
// the ADR are here; step 8, whether the subject is somebody the backend lets
// in, is the backend's own decision and is left to the caller.
package assertiontest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// clockSkew is how far either way of the backend's clock an assertion's times
// may be. The ADR asks for some tens of seconds.
const clockSkew = 30 * time.Second

// Expect is what the backend has configured for itself. None of it is read from
// the assertion or from the request it arrived on.
type Expect struct {
	// Issuer is the origin of the central authentication host.
	Issuer string
	// Audience is the backend's own public host name.
	Audience string
	// Now is the backend's clock.
	Now time.Time
}

// Claims is what a verified assertion says.
type Claims struct {
	Issuer    string
	Subject   string
	Audience  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Verify checks an assertion against a JWKS document and returns its claims.
func Verify(jwks []byte, token string, want Expect) (Claims, error) {
	// 1. There is one.
	if token == "" {
		return Claims{}, errors.New("no assertion")
	}

	// 2. A compact JWS, EdDSA, of gated's type. The algorithm is fixed
	// here rather than taken from the header.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("not a JWS in compact form")
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := decode(parts[0], &header); err != nil {
		return Claims{}, fmt.Errorf("the header: %w", err)
	}
	if header.Alg != "EdDSA" {
		return Claims{}, fmt.Errorf("alg %q is not EdDSA", header.Alg)
	}
	if header.Typ != "gated-assertion+jwt" {
		return Claims{}, fmt.Errorf("typ %q is not a gated assertion", header.Typ)
	}

	// 3. The key it names is in the configured set.
	key, err := lookup(jwks, header.Kid)
	if err != nil {
		return Claims{}, err
	}

	// 4. The signature holds.
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, errors.New("the signature is not base64url")
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
		return Claims{}, errors.New("the signature does not verify")
	}

	var body struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Aud string `json:"aud"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	if err := decode(parts[1], &body); err != nil {
		return Claims{}, fmt.Errorf("the claims: %w", err)
	}

	// 5. The configured issuer.
	if body.Iss != want.Issuer {
		return Claims{}, fmt.Errorf("issued by %q, not %q", body.Iss, want.Issuer)
	}
	// 6. The configured host, never the request's Host header.
	if body.Aud != want.Audience {
		return Claims{}, fmt.Errorf("issued for %q, not %q", body.Aud, want.Audience)
	}
	// 7. Within its time.
	issued, expires := time.Unix(body.Iat, 0), time.Unix(body.Exp, 0)
	if !want.Now.Before(expires) {
		return Claims{}, errors.New("expired")
	}
	if issued.After(want.Now.Add(clockSkew)) {
		return Claims{}, errors.New("issued in the future")
	}
	if body.Sub == "" {
		return Claims{}, errors.New("names nobody")
	}

	return Claims{
		Issuer:    body.Iss,
		Subject:   body.Sub,
		Audience:  body.Aud,
		IssuedAt:  issued,
		ExpiresAt: expires,
	}, nil
}

// lookup finds an Ed25519 key by its identifier in a JWKS document.
func lookup(jwks []byte, kid string) (ed25519.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		return nil, fmt.Errorf("the key set is not JSON: %w", err)
	}
	for _, k := range set.Keys {
		if k.Kid != kid || kid == "" {
			continue
		}
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			return nil, fmt.Errorf("key %q is not an Ed25519 key", kid)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %q is malformed", kid)
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, fmt.Errorf("no key %q in the key set", kid)
}

func decode(segment string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return errors.New("not base64url")
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return errors.New("not JSON")
	}
	return nil
}
