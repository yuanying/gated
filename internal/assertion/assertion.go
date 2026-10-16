// Package assertion is what gated tells a backend about the request it
// forwards: a short signed statement that it authenticated this subject for
// this host (ADR 0034).
//
// The statement is a JWS in compact form, signed with Ed25519 and nothing else,
// so that a backend can check it with whatever JOSE library its language has
// and the public keys gated publishes as a JWKS. Signing, the key set and its
// encodings are pure functions here; where the keys come from — a Secret every
// replica reads — is somebody else's problem.
package assertion

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/yuanying/gated/internal/routing"
)

// The header the assertion travels in, and the prefix gated reserves for the
// headers it sets itself. Whatever a client sends under that prefix is taken
// off before anything is forwarded, so that behind gated a Gated- header is
// always one gated wrote (ADR 0034).
const (
	HeaderPrefix = "Gated-"
	Header       = HeaderPrefix + "Assertion"
)

// The fixed parts of the wire form.
const (
	// Algorithm is the only one gated signs with. A backend that accepts
	// this and nothing else is not open to an algorithm being swapped.
	Algorithm = "EdDSA"
	// Type separates an assertion from every other kind of JWT.
	Type = "gated-assertion+jwt"
	// Lifetime is how long an assertion is good for. It covers one request
	// and the clock difference between gated and the backend.
	Lifetime = 60 * time.Second
)

// The entries of the Secret the keys are kept in.
const (
	// SigningKeyEntry holds the one private key assertions are signed with,
	// PEM-encoded PKCS #8.
	SigningKeyEntry = "signing-key"
	// PublishedKeysEntry holds the keys that are published but never sign
	// with: the next key during a rotation, and the previous one after it.
	// It is zero or more PEM blocks, each a PKCS #8 private key or a PKIX
	// public key; only the public half is ever used.
	PublishedKeysEntry = "published-keys"
)

// The PEM block types the key entries are read from.
const (
	privateKeyBlock = "PRIVATE KEY"
	publicKeyBlock  = "PUBLIC KEY"
)

// KeySet is the keys one installation signs and publishes with.
type KeySet struct {
	signing   ed25519.PrivateKey
	signingID string
	// published is every public key in the set, the signing key's first,
	// each once.
	published []publicKey
}

type publicKey struct {
	id  string
	key ed25519.PublicKey
}

// ParseKeySet reads the keys out of a Secret's data.
//
// Anything it cannot read is an error for the whole set, published keys
// included. A set read only as far as it goes would be a rotation that lost a
// key without anybody being told, and the requests signed with it failing at
// the backend for no reason anybody could see.
func ParseKeySet(data map[string][]byte) (*KeySet, error) {
	signing, err := parseSigningKey(data[SigningKeyEntry])
	if err != nil {
		return nil, fmt.Errorf("the %q entry: %w", SigningKeyEntry, err)
	}
	set := &KeySet{signing: signing}
	pub, ok := signing.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("the %q entry has no public half", SigningKeyEntry)
	}
	set.signingID = set.add(pub)

	rest := data[PublishedKeysEntry]
	for len(bytes.TrimSpace(rest)) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("the %q entry holds something that is not PEM", PublishedKeysEntry)
		}
		key, err := parsePublic(block)
		if err != nil {
			return nil, fmt.Errorf("the %q entry: %w", PublishedKeysEntry, err)
		}
		set.add(key)
	}
	return set, nil
}

// add puts a public key into the published set unless it is already there, and
// returns its identifier.
func (k *KeySet) add(key ed25519.PublicKey) string {
	id := KeyID(key)
	for _, existing := range k.published {
		if existing.id == id {
			return id
		}
	}
	k.published = append(k.published, publicKey{id: id, key: key})
	return id
}

func parseSigningKey(raw []byte) (ed25519.PrivateKey, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("is missing")
	}
	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("is not PEM")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("holds more than one key; exactly one signs")
	}
	if block.Type != privateKeyBlock {
		return nil, fmt.Errorf("is a %q block, not a %q", block.Type, privateKeyBlock)
	}
	return parsePrivate(block.Bytes)
}

func parsePrivate(der []byte) (ed25519.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("is not a PKCS #8 private key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("is a %T, not an Ed25519 key", parsed)
	}
	return key, nil
}

func parsePublic(block *pem.Block) (ed25519.PublicKey, error) {
	switch block.Type {
	case privateKeyBlock:
		private, err := parsePrivate(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := private.Public().(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("has a private key with no public half")
		}
		return key, nil
	case publicKeyBlock:
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("is not a PKIX public key: %w", err)
		}
		key, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("is a %T, not an Ed25519 key", parsed)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("holds a %q block; only %q and %q are read", block.Type, privateKeyBlock, publicKeyBlock)
	}
}

// GenerateSecretData makes a new signing key, in the form ParseKeySet reads.
// Nothing is published besides it: a fresh installation has nothing to rotate
// from.
func GenerateSecretData() (map[string][]byte, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating a signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encoding the signing key: %w", err)
	}
	return map[string][]byte{
		SigningKeyEntry: pem.EncodeToMemory(&pem.Block{Type: privateKeyBlock, Bytes: der}),
	}, nil
}

// KeyID names a key by its JWK thumbprint (RFC 7638), which anybody holding the
// public key can work out for themselves.
func KeyID(key ed25519.PublicKey) string {
	// The members in lexical order and nothing else, as the RFC requires.
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(key) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Issuer is the iss gated writes: the https origin of the central
// authentication host, port and all, spelled the way the login's redirect URI
// is.
func Issuer(authHost string) string {
	host := authHost
	port := ""
	if h, p, err := net.SplitHostPort(authHost); err == nil {
		host, port = h, p
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if port != "" {
		return "https://" + net.JoinHostPort(host, port)
	}
	return "https://" + host
}

// Claims is what an assertion says.
//
// It says who gated authenticated and for which host. It does not say that the
// request was allowed, or by which rule: a backend that reads it decides for
// itself whether this subject is somebody it lets in (ADR 0034).
type Claims struct {
	// Issuer is the origin of the central authentication host.
	Issuer string
	// Subject is the principal, in the vocabulary of ADR 0002.
	Subject string
	// Audience is the host the request was for. Any port is dropped and it
	// is lower-cased; a wildcard rule that matched is not what is written,
	// the name that was asked for is.
	Audience string
	// IssuedAt is when it was signed. It expires Lifetime later.
	IssuedAt time.Time
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// body is the wire form of the claims. The set is closed: a test reads it
// back, so that nothing a backend might come to rely on is added by accident.
type body struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// Sign renders the claims as a compact JWS signed with the signing key.
func (k *KeySet) Sign(c Claims) (string, error) {
	if k == nil || k.signing == nil {
		return "", errors.New("there is no signing key")
	}
	audience := routing.CanonicalHost(c.Audience)
	switch {
	case c.Issuer == "":
		return "", errors.New("an assertion must name its issuer")
	case c.Subject == "":
		return "", errors.New("an assertion must name a subject")
	case audience == "":
		return "", errors.New("an assertion must name the host it is for")
	case c.IssuedAt.IsZero():
		return "", errors.New("an assertion must say when it was issued")
	}

	head, err := json.Marshal(header{Alg: Algorithm, Typ: Type, Kid: k.signingID})
	if err != nil {
		return "", fmt.Errorf("encoding the header: %w", err)
	}
	claims, err := json.Marshal(body{
		Iss: c.Issuer,
		Sub: c.Subject,
		Aud: audience,
		Iat: c.IssuedAt.Unix(),
		Exp: c.IssuedAt.Add(Lifetime).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("encoding the claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString(claims)
	signature := ed25519.Sign(k.signing, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// jwk is one published key. Only the public members exist here, so there is no
// field a private value could be put into by mistake.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

// JWKS renders every public key in the set, the signing key's first, as a JWK
// set (RFC 7517).
func (k *KeySet) JWKS() ([]byte, error) {
	if k == nil {
		return nil, errors.New("there are no keys")
	}
	keys := make([]jwk, 0, len(k.published))
	for _, p := range k.published {
		keys = append(keys, jwk{
			Kty: "OKP",
			Crv: "Ed25519",
			Alg: Algorithm,
			Use: "sig",
			Kid: p.id,
			X:   base64.RawURLEncoding.EncodeToString(p.key),
		})
	}
	return json.Marshal(struct {
		Keys []jwk `json:"keys"`
	}{Keys: keys})
}
