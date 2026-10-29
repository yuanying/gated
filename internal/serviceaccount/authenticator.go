package serviceaccount

import (
	"context"
	"crypto/sha256"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

// headerName is the header a ServiceAccount token arrives in.
const headerName = "Authorization"

// DefaultTTL is how long an answer from the API server is remembered when
// nothing else is said.
const DefaultTTL = time.Minute

// DefaultMaxEntries bounds how many answers are remembered at once. Every
// ServiceAccount that calls through gated costs one, and so does every token
// the API server refused; well past what a cluster of this size has, and small
// enough that a client sending a new invented token on every request cannot
// make the memory grow without end.
const DefaultMaxEntries = 4096

// reviewTimeout bounds how long a request waits on the API server. A request
// that waits longer is answered as though the token had not been presented,
// which is what an API server that is not answering amounts to.
const reviewTimeout = 5 * time.Second

// Authenticator establishes which ServiceAccount is behind a request that
// carries one of its tokens, and spends the credential.
//
// It sits beside the AccessToken authenticator and works the same way: it
// names the caller and decides nothing. What follows is the same decision a
// session cookie or an AccessToken leads to (ADR 0004).
type Authenticator struct {
	// Audience is the one audience a token must have been issued for.
	// Required.
	Audience string
	// Reviewer asks the API server. Required.
	Reviewer Reviewer
	// TTL is how long an answer is remembered. Zero is DefaultTTL. An
	// accepted token is never remembered past its own expiry.
	TTL time.Duration
	// MaxEntries bounds the memory. Zero is DefaultMaxEntries.
	MaxEntries int
	// Now is the clock. Nil is time.Now.
	Now func() time.Time
	// Metrics counts what was presented. Nil counts nothing.
	Metrics *Metrics
	// Log records tokens that were not believed. Never the token.
	Log logr.Logger

	mu       sync.Mutex
	answered map[[sha256.Size]byte]answer
}

// answer is what is remembered about one token, keyed by its digest so that
// the memory holds nothing that could be presented.
type answer struct {
	subject string
	reason  Reason
	until   time.Time
}

var identityContextKey = &struct{ name string }{"serviceaccount-subject"}

// Wrap returns a handler that reads a ServiceAccount token, if one was
// presented, before calling next.
//
// A token that is accepted is taken off the request: it is gated's credential,
// and forwarding it would let anything behind the proxy present it elsewhere
// as the ServiceAccount (ADR 0022). Anything else is left exactly as it came,
// so that a backend checking the same token for its own audience goes on
// doing so.
func (a *Authenticator) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := Bearer(r.Header.Get(headerName))
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		subject, reason := a.authenticate(r.Context(), token)
		a.Metrics.token(reason)
		if reason != Accepted {
			next.ServeHTTP(w, r)
			return
		}
		r.Header.Del(headerName)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityContextKey, subject)))
	})
}

// Subject names the caller, for the authorisation middleware. Like the
// AccessToken authenticator, it reads only what Wrap established.
func (a *Authenticator) Subject(r *http.Request) string {
	subject, _ := SubjectFromContext(r.Context())
	return subject
}

// SubjectFromContext returns the ServiceAccount a request was authenticated
// as, if one was.
func SubjectFromContext(ctx context.Context) (string, bool) {
	subject, ok := ctx.Value(identityContextKey).(string)
	return subject, ok
}

func (a *Authenticator) authenticate(ctx context.Context, token string) (string, Reason) {
	now := a.now()
	log := a.Log.V(1)

	expiry, reason := precheck(token, a.Audience, now)
	if reason != "" {
		log.Info("a service account token was not accepted", "reason", reason)
		return "", reason
	}

	key := sha256.Sum256([]byte(token))
	if remembered, ok := a.recall(key, now); ok {
		if remembered.reason != Accepted {
			log.Info("a service account token was not accepted", "reason", remembered.reason, "remembered", true)
		}
		return remembered.subject, remembered.reason
	}

	ctx, cancel := context.WithTimeout(ctx, reviewTimeout)
	defer cancel()
	review, err := a.Reviewer.Review(ctx, token, a.Audience)
	if err != nil {
		// Not an answer about the token, so nothing is remembered. A
		// token remembered from before goes on working; this one is
		// asked about again on the next request.
		a.Metrics.review(reviewError)
		a.Log.Error(err, "a service account token could not be reviewed", "reason", ReviewFailed)
		return "", ReviewFailed
	}
	if review.Authenticated {
		a.Metrics.review(reviewAuthenticated)
	} else {
		a.Metrics.review(reviewUnauthenticated)
	}

	subject, reason := Judge(review, a.Audience)
	until := now.Add(a.ttl())
	if reason == Accepted && !expiry.IsZero() && expiry.Before(until) {
		until = expiry
	}
	a.remember(key, answer{subject: subject, reason: reason, until: until}, now)

	if reason != Accepted {
		log.Info("a service account token was not accepted", "reason", reason, "error", review.Error, "username", review.Username)
	}
	return subject, reason
}

func (a *Authenticator) recall(key [sha256.Size]byte, now time.Time) (answer, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	remembered, ok := a.answered[key]
	if !ok {
		return answer{}, false
	}
	if !now.Before(remembered.until) {
		delete(a.answered, key)
		return answer{}, false
	}
	return remembered, true
}

// remember keeps an answer, unless the memory is full of answers that are
// still good. Then it is dropped: asking the API server again is the cost of
// being sent more tokens than there is room for, and evicting a good answer to
// make room would hand that cost to a caller who did nothing unusual.
func (a *Authenticator) remember(key [sha256.Size]byte, ans answer, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.answered == nil {
		a.answered = map[[sha256.Size]byte]answer{}
	}
	if len(a.answered) >= a.maxEntries() {
		for k, v := range a.answered {
			if !now.Before(v.until) {
				delete(a.answered, k)
			}
		}
		if len(a.answered) >= a.maxEntries() {
			return
		}
	}
	a.answered[key] = ans
}

func (a *Authenticator) now() time.Time {
	if a.Now == nil {
		return time.Now()
	}
	return a.Now()
}

func (a *Authenticator) ttl() time.Duration {
	if a.TTL <= 0 {
		return DefaultTTL
	}
	return a.TTL
}

func (a *Authenticator) maxEntries() int {
	if a.MaxEntries <= 0 {
		return DefaultMaxEntries
	}
	return a.MaxEntries
}
