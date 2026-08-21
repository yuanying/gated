// Package authn establishes who is behind a request and runs the login that
// makes that possible: the signed session cookie, the central authentication
// host, and the handoff that carries an identity from that host back to the
// protected one (ADR 0003).
//
// Signing and verification are pure functions over a key and a token. They
// touch neither Kubernetes nor an *http.Request, so every way of handing back
// something other than what was issued — a rewritten claim, a replaced
// signature, an expired token, a rotated key — is enumerated in a table test
// (ADR 0007). Where the key comes from is somebody else's problem.
package authn

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yuanying/gated/internal/routing"
)

// Kind separates the three things a signature attests to. They are spelled
// short because a session travels in a cookie on every request.
//
// Keeping them apart is not decoration: the thirty-second token that carries a
// visitor from the central authentication host to a protected one must not be
// keepable as a session, and the OAuth state parameter must not be either.
type Kind string

const (
	// KindSession is a logged-in session at one protected host.
	KindSession Kind = "s"
	// KindHandoff carries an identity from the central authentication host
	// to one protected host, once, within seconds.
	KindHandoff Kind = "h"
	// KindState is the OAuth state parameter, which remembers where the
	// visitor was going while they are away at the identity provider.
	KindState Kind = "t"
)

// MinKeySize is the shortest signing key that may be used. It is the output
// size of the hash, below which the key is the weakest part of the signature.
const MinKeySize = 32

// maxTokenSize bounds what will be parsed at all. A cookie is written by
// whoever holds the browser, and there is no reason for a real one to come
// anywhere near this.
const maxTokenSize = 4096

// issuedAtLeeway is how far ahead of this replica's clock a token may claim to
// have been issued. Replicas sign for each other, and their clocks differ.
const issuedAtLeeway = 2 * time.Minute

// Token is what a signature attests to.
//
// It says who the visitor is, which host the answer is for, and when it stops
// being true. It never says what they may do: permissions are evaluated per
// request against NetworkRole and NetworkRoleBinding, so that revoking one
// takes effect on the next request rather than on the next login (ADR 0003).
type Token struct {
	// Kind is what this token is for.
	Kind Kind
	// Subject is the principal, in the vocabulary of ADR 0002, except on a
	// state token where it is the nonce matched against a cookie.
	Subject string
	// Audience is the host the token is good at, and nowhere else.
	Audience string
	// Next is where to continue. A handoff carries a path on its audience;
	// a state token carries the absolute URL the visitor was going to.
	Next string
	// Binding ties a handoff to the browser that started the login: it is
	// the digest of a nonce only that browser holds (see LoginBinding).
	Binding string
	// Provider names the identity provider a state token belongs to.
	Provider string

	IssuedAt  time.Time
	ExpiresAt time.Time
}

// payload is the wire form. The names are short and the set is closed: the
// test that reads them back is what keeps a permission from ever being added.
type payload struct {
	Kind     Kind   `json:"k"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	Next     string `json:"nxt,omitempty"`
	Binding  string `json:"bnd,omitempty"`
	Provider string `json:"prv,omitempty"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
}

// Sign renders a token as a string that only a holder of the key can produce.
//
// It refuses anything Verify would refuse, so that a mistake surfaces where the
// token is made rather than as a login that fails for no visible reason.
func Sign(key []byte, t Token) (string, error) {
	if err := checkKey(key); err != nil {
		return "", err
	}
	switch t.Kind {
	case KindSession, KindHandoff, KindState:
	default:
		return "", fmt.Errorf("%q is not a kind of token gated issues", t.Kind)
	}
	if t.Subject == "" {
		return "", errors.New("a token must name a subject")
	}
	if t.Audience == "" {
		return "", errors.New("a token must name the host it is good at")
	}
	if t.ExpiresAt.IsZero() {
		return "", errors.New("a token must expire")
	}
	if !t.ExpiresAt.After(t.IssuedAt) {
		return "", errors.New("a token must expire after it was issued")
	}
	if t.Kind == KindHandoff {
		if err := CheckPath(t.Next); err != nil {
			return "", err
		}
	}

	body, err := json.Marshal(payload{
		Kind:     t.Kind,
		Subject:  t.Subject,
		Audience: routing.CanonicalHost(t.Audience),
		Next:     t.Next,
		Binding:  t.Binding,
		Provider: t.Provider,
		IssuedAt: t.IssuedAt.Unix(),
		Expires:  t.ExpiresAt.Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("encoding the token: %w", err)
	}
	return signEncoded(key, base64.RawURLEncoding.EncodeToString(body))
}

// Expect is what a token has to be for Verify to hand it back.
type Expect struct {
	// Kind is what the token must be. A session offered as a handoff, or
	// the other way round, is refused.
	Kind Kind
	// Audience is the host the token must have been issued for. It is
	// required: there is no such thing as a token good at any host.
	Audience string
	// Now is the moment the expiry is judged against.
	Now time.Time
}

// Verify checks a token and returns what it says.
//
// The signature is checked first and with a constant-time comparison, and
// nothing is parsed as JSON until it has held: the string comes from whoever
// holds the browser, so its contents mean nothing until the key says they do.
func Verify(key []byte, raw string, want Expect) (Token, error) {
	if err := checkKey(key); err != nil {
		return Token{}, err
	}
	if want.Audience == "" {
		return Token{}, errors.New("a token can only be verified against a host")
	}
	if len(raw) == 0 || len(raw) > maxTokenSize {
		return Token{}, errors.New("malformed token")
	}

	encoded, signature, found := strings.Cut(raw, ".")
	if !found || strings.Contains(signature, ".") {
		return Token{}, errors.New("malformed token")
	}
	offered, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return Token{}, errors.New("malformed token")
	}
	if !hmac.Equal(offered, mac(key, encoded)) {
		return Token{}, errors.New("the token is not signed by this installation")
	}

	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Token{}, errors.New("malformed token")
	}
	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		return Token{}, errors.New("malformed token")
	}

	if p.Kind != want.Kind {
		return Token{}, fmt.Errorf("the token is a %q, not a %q", p.Kind, want.Kind)
	}
	if p.Audience != routing.CanonicalHost(want.Audience) {
		return Token{}, fmt.Errorf("the token was issued for %q, not for %q", p.Audience, want.Audience)
	}

	issued, expires := time.Unix(p.IssuedAt, 0), time.Unix(p.Expires, 0)
	if !want.Now.Before(expires) {
		return Token{}, errors.New("the token has expired")
	}
	if issued.After(want.Now.Add(issuedAtLeeway)) {
		return Token{}, errors.New("the token was issued in the future")
	}

	return Token{
		Kind:      p.Kind,
		Subject:   p.Subject,
		Audience:  p.Audience,
		Next:      p.Next,
		Binding:   p.Binding,
		Provider:  p.Provider,
		IssuedAt:  issued,
		ExpiresAt: expires,
	}, nil
}

// CheckPath reports whether a string is somewhere on the host that will be
// asked to go there. Only a rooted path qualifies: "//host" and
// "https://host" both leave for somewhere else, and a relative path is
// ambiguous. This is the open-redirect check on the last leg of the login.
func CheckPath(p string) error {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return fmt.Errorf("%q is not a path on this host", p)
	}
	return nil
}

func checkKey(key []byte) error {
	if len(key) < MinKeySize {
		return fmt.Errorf("the signing key is %d bytes; at least %d are required", len(key), MinKeySize)
	}
	return nil
}

func signEncoded(key []byte, encoded string) (string, error) {
	if err := checkKey(key); err != nil {
		return "", err
	}
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac(key, encoded)), nil
}

func mac(key []byte, encoded string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(encoded))
	return h.Sum(nil)
}
