package assertion

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-logr/logr"
)

// jwksCacheControl lets a backend hold the key set for five minutes. A key is
// published before it signs anything (ADR 0034), so the wait in the first step
// of a rotation is this plus the interval replicas re-read the Secret at.
const jwksCacheControl = "public, max-age=300"

// jwksContentType is the media type RFC 7517 registers for a JWK set.
const jwksContentType = "application/jwk-set+json"

// KeySource hands out the key set in force.
//
// It is an interface because the keys live in a Secret shared by every replica
// (ADR 0006) and are rotated under a running process. Nothing in this package
// knows that.
type KeySource interface {
	KeySet(ctx context.Context) (*KeySet, error)
}

// StaticKeys is a key set held in memory, for tests.
type StaticKeys struct{ Set *KeySet }

// KeySet returns the held set.
func (s StaticKeys) KeySet(context.Context) (*KeySet, error) {
	if s.Set == nil {
		return nil, errors.New("no key set has been read yet")
	}
	return s.Set, nil
}

// Signer makes the assertion for one forwarded request.
type Signer struct {
	// Keys hands out the key set. Required.
	Keys KeySource
	// Issuer is the iss written, from Issuer. Required.
	Issuer string
	// Now reads the clock. Nil means time.Now.
	Now func() time.Time
}

// Assert vouches that subject was authenticated for a request to host.
//
// It is made afresh for every request and never reused: what keeps a copy
// lifted from a log from being useful is its minute of life.
func (s *Signer) Assert(ctx context.Context, subject, host string) (string, error) {
	keys, err := s.Keys.KeySet(ctx)
	if err != nil {
		return "", err
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	return keys.Sign(Claims{Issuer: s.Issuer, Subject: subject, Audience: host, IssuedAt: now})
}

// JWKSHandler publishes the public keys a backend verifies assertions with.
type JWKSHandler struct {
	// Keys hands out the key set. Required.
	Keys KeySource
	// Log records a request that could not be answered.
	Log logr.Logger
}

func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "the key set is only read", http.StatusMethodNotAllowed)
		return
	}

	doc, err := h.document(r.Context())
	if err != nil {
		// An empty set held in a cache would leave a backend unable to
		// verify anything until it expired. Say nothing that lasts.
		h.Log.Info("the key set was asked for before the keys could be read", "reason", err.Error())
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "the key set cannot be read just now; try again", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", jwksContentType)
	w.Header().Set("Cache-Control", jwksCacheControl)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	w.Write(doc)
}

func (h *JWKSHandler) document(ctx context.Context) ([]byte, error) {
	keys, err := h.Keys.KeySet(ctx)
	if err != nil {
		return nil, err
	}
	return keys.JWKS()
}
