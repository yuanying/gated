package authn

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-logr/logr"

	"github.com/yuanying/gated/internal/routing"
)

// DefaultSessionTTL is how long a session lasts when nothing says otherwise.
//
// It is short on purpose. A signed cookie cannot be revoked (ADR 0003), so the
// expiry is the only thing that ends one; permissions are re-evaluated per
// request, so what a short life bounds is the window in which an identifier
// that turned out to be untrustworthy is still believed.
const DefaultSessionTTL = 12 * time.Hour

// KeySource hands out the key sessions are signed with.
//
// It is an interface because the key lives in a Secret shared by every replica
// (ADR 0006) and may be rotated under a running process. Nothing in this
// package knows that.
type KeySource interface {
	SigningKey(ctx context.Context) ([]byte, error)
}

// StaticKey is a key held in memory, for tests and for callers that read it
// themselves.
type StaticKey []byte

// SigningKey returns the held key.
func (k StaticKey) SigningKey(context.Context) ([]byte, error) {
	if len(k) == 0 {
		return nil, errors.New("no signing key has been read yet")
	}
	return k, nil
}

// Sessions issues the cookie that says who a visitor is on one host, and reads
// it back.
//
// It is the SubjectResolver the authorisation middleware asks (ADR 0018): one
// seam, filled here for browsers and by tokens elsewhere, with the decision
// itself unchanged.
type Sessions struct {
	// Keys hands out the signing key. Required.
	Keys KeySource
	// TTL is how long an issued session lasts. Zero means DefaultSessionTTL.
	TTL time.Duration
	// Now reads the clock. Nil means time.Now.
	Now func() time.Time
	// Log records the reasons a cookie was not believed, at V(1): a bad
	// cookie is ordinary, and one line per request would drown the log.
	Log logr.Logger
}

// Subject returns who the request's cookie says this is, or the empty string.
//
// Every failure is anonymity rather than an error. A cookie that does not
// verify is indistinguishable from no cookie, and the caller's next step is
// the same either way: decide what an anonymous visitor may do.
func (s *Sessions) Subject(r *http.Request) string {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}
	key, err := s.Keys.SigningKey(r.Context())
	if err != nil {
		// Believing a cookie nothing verified is the one answer that is
		// worse than logging everybody out.
		s.Log.V(1).Info("a session was offered before the signing key could be read", "host", r.Host)
		return ""
	}

	token, err := Verify(key, cookie.Value, Expect{
		Kind: KindSession, Audience: r.Host, Now: s.now(),
	})
	if err != nil {
		s.Log.V(1).Info("a session was not believed", "host", r.Host, "reason", err.Error())
		return ""
	}
	return token.Subject
}

// Issue writes a session cookie for one host onto a response.
func (s *Sessions) Issue(ctx context.Context, w http.ResponseWriter, host, subject string) error {
	key, err := s.Keys.SigningKey(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	ttl := s.ttl()
	value, err := Sign(key, Token{
		Kind:      KindSession,
		Subject:   subject,
		Audience:  routing.CanonicalHost(host),
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	})
	if err != nil {
		return err
	}
	http.SetCookie(w, SessionCookie(value, ttl))
	return nil
}

func (s *Sessions) now() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

func (s *Sessions) ttl() time.Duration {
	if s.TTL <= 0 {
		return DefaultSessionTTL
	}
	return s.TTL
}

// KeyFunc adapts a function to a KeySource, so that whatever reads the Secret
// does not have to know about this package.
type KeyFunc func(ctx context.Context) ([]byte, error)

// SigningKey calls the function.
func (f KeyFunc) SigningKey(ctx context.Context) ([]byte, error) { return f(ctx) }
