package accesstoken

import (
	"context"
	"net/http"

	"github.com/go-logr/logr"
)

// headerName is the header both doors arrive through.
const headerName = "Authorization"

// Usage is told that a token was presented, so that the last-used time can be
// written back somewhere far away from the request path.
//
// Implementations must not block: this is called while a request is being
// served, and an API server that is slow to answer must not be something a
// caller waits on.
type Usage interface {
	Used(namespace, name string)
}

// Authenticator establishes who is behind a request that carries a token, and
// spends the credential.
//
// It runs before the authorisation decision and does nothing but name the
// caller. The decision that follows is the same one a browser's session cookie
// leads to — there are two ways in and one set of rules (ADR 0004).
type Authenticator struct {
	// Tokens holds the set in force. Required.
	Tokens *Store
	// Usage is told when a token is presented. Nil records nothing.
	Usage Usage
	// Log records tokens that were offered and not believed, at V(1): a
	// wrong credential is ordinary, and one line per request would drown
	// the log.
	Log logr.Logger
}

// subjectContextKey carries the identity from the middleware to the resolver.
type contextKey struct{ name string }

var identityContextKey = &contextKey{"access-token-identity"}

// Wrap returns a handler that reads a token, if one was presented, before
// calling next.
//
// A credential gated recognises is removed from the request. It is gated's
// credential and not the backend's, and forwarding it would let anything
// behind the proxy turn round and act as whoever presented it. Anything gated
// does not recognise is passed through untouched, so that a backend doing its
// own authentication goes on doing it.
func (a *Authenticator) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented, ok := Credential(r.Header.Get(headerName))
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		snapshot, loaded := a.Tokens.Load()
		if !loaded {
			// Not "this token is wrong" but "this replica cannot
			// say yet". The readiness check keeps traffic away
			// while that is true; a request that arrives anyway
			// falls through as anonymous and is refused by the
			// rules, not here.
			a.Log.V(1).Info("a token was offered before the tokens were read", "host", r.Host)
			next.ServeHTTP(w, r)
			return
		}

		identity, found := snapshot.Lookup(presented)
		if !found {
			a.Log.V(1).Info("a token was not recognised", "host", r.Host, "path", r.URL.Path)
			next.ServeHTTP(w, r)
			return
		}

		if a.Usage != nil {
			a.Usage.Used(identity.Namespace, identity.Name)
		}
		r.Header.Del(headerName)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityContextKey, identity)))
	})
}

// Subject names the caller, for the authorisation middleware.
//
// It reads what Wrap established and never looks at the header itself. One
// place spends a credential; asking twice would mean two answers could differ,
// and the one the decision used would not be the one the log recorded.
func (a *Authenticator) Subject(r *http.Request) string {
	identity, _ := IdentityFromContext(r.Context())
	return identity.Subject
}

// IdentityFromContext returns the token a request was authenticated with.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityContextKey).(Identity)
	return identity, ok
}

// SubjectFromContext returns the subject a token named, if one did.
func SubjectFromContext(ctx context.Context) (string, bool) {
	identity, ok := IdentityFromContext(ctx)
	return identity.Subject, ok
}
