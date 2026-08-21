package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/go-logr/logr"

	"github.com/yuanying/gated/internal/authz"
	"github.com/yuanying/gated/internal/routing"
)

// The paths gated answers on a protected host for its own sake. They are
// prefixed so that they cannot collide with an application's own routes, and
// they are constants here because both sides of the login flow have to agree
// on them: the redirect built below, and the handlers of the central
// authentication host.
const (
	// LoginPath is where the central authentication host takes over.
	LoginPath = "/__gated/login"
	// CallbackPath is where a protected host is handed the result and
	// issues its own cookie (ADR 0003).
	CallbackPath = "/__gated/callback"
	// NextParam carries the address to return to once the login is done.
	NextParam = "next"
)

// authenticateRealm is the realm offered to clients that cannot follow a
// redirect. BASIC is the scheme because that is the door a token comes through
// for clients whose login command cannot be changed (ADR 0004); the realm names
// gated itself and no deployment of it.
const authenticateRealm = `Basic realm="gated"`

// PolicyStore holds the permissions currently in force.
//
// It is the same arrangement as the routing table: an immutable snapshot
// behind an atomic pointer, rebuilt whole and swapped in, so that a request
// being authorised finishes against the set it started with and the read side
// takes no locks.
//
// The difference is what an empty store means. An empty routing table matches
// nothing and answers 404; an empty permission set protects nothing and allows
// everything, because that is what fail-open means (ADR 0002). "Nothing is
// protected" and "nothing has been loaded yet" must therefore not be the same
// value, so the store reports whether a snapshot has arrived at all.
type PolicyStore struct {
	current atomic.Pointer[policySnapshot]
}

type policySnapshot struct {
	policies *authz.PolicySet
}

// Store puts a snapshot into force.
func (s *PolicyStore) Store(policies *authz.PolicySet) {
	if s == nil {
		return
	}
	s.current.Store(&policySnapshot{policies: policies})
}

// Load returns the snapshot in force. The second result is false until the
// first snapshot has been stored, and a caller that ignores it authorises
// against an empty world.
func (s *PolicyStore) Load() (*authz.PolicySet, bool) {
	if s == nil {
		return nil, false
	}
	snapshot := s.current.Load()
	if snapshot == nil {
		return nil, false
	}
	return snapshot.policies, true
}

// Ready reports whether the permissions have been loaded, in the shape a
// health check wants. A replica that has not read them yet cannot tell an
// unprotected resource from one it has not heard about, so it is not ready to
// take traffic.
func (s *PolicyStore) Ready(*http.Request) error {
	if _, ok := s.Load(); !ok {
		return fmt.Errorf("the authorisation policies have not been loaded yet")
	}
	return nil
}

// SubjectResolver names the principal behind a request.
//
// This is the seam authentication plugs into: the decision needs a subject,
// and where that subject comes from — a signed cookie, a bearer token, the
// password field of a BASIC header — is not its business (ADR 0002, 0004).
// Until those exist, every caller is anonymous.
type SubjectResolver interface {
	// Subject returns the principal behind the request, or the empty
	// string when the request carries no identity gated trusts.
	Subject(r *http.Request) string
}

// Authorization decides whether a routed request may proceed, and turns that
// decision into a response.
//
// Everything HTTP about the answer lives here rather than in the decision
// itself (ADR 0007): whether the caller is a browser, which status code says
// so, and where a login lives are all questions about a request, and the
// decision is deliberately unable to see one.
type Authorization struct {
	// Policies holds the permissions in force. Required.
	Policies *PolicyStore
	// Subjects names the caller. A nil resolver makes every caller
	// anonymous, which is what stage 5 has before authentication exists.
	Subjects SubjectResolver
	// AuthHost is the central authentication host (ADR 0003). Without it
	// there is nowhere to send anybody, and a caller who could have logged
	// in is challenged instead.
	AuthHost string
	// Log records refusals. The zero Logger discards.
	Log logr.Logger
}

// Wrap returns a handler that authorises before calling next.
func (a *Authorization) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		match, routed := MatchFromContext(r.Context())
		if !routed {
			// The proxy answers 404 before this runs, so arriving
			// here unrouted means the chain is wired wrongly. Say
			// so rather than deciding against a target of nothing,
			// which would allow the request through.
			a.Log.Info("a request reached authorisation without a route",
				"host", r.Host, "path", r.URL.Path)
			http.Error(w, "this request was not routed", http.StatusInternalServerError)
			return
		}

		policies, loaded := a.Policies.Load()
		if !loaded {
			// Nothing is known yet, and "nothing is known" reads
			// exactly like "nothing is protected". Refuse for the
			// moment it takes to read the cluster.
			a.Log.Info("a request arrived before the permissions were loaded",
				"host", r.Host, "path", r.URL.Path)
			http.Error(w, "the authorisation policies are not loaded yet", http.StatusServiceUnavailable)
			return
		}

		subject := ""
		if a.Subjects != nil {
			subject = a.Subjects.Subject(r)
		}

		decision := policies.Evaluate(authz.Request{
			Subject: subject,
			Host:    r.Host,
			// The path and method are read as they arrived. Routing
			// does not normalise them either (ADR 0012), so what is
			// authorised and what is forwarded are the same.
			Path:   r.URL.Path,
			Method: r.Method,
			Target: authz.ResourceRef{Namespace: match.Ingress.Namespace, Name: match.Ingress.Name},
		})

		switch decision {
		case authz.Allow:
			next.ServeHTTP(w, withSubject(r, subject))
		case authz.RequireLogin:
			a.requireLogin(w, r)
		default:
			a.Log.V(1).Info("refused", "host", r.Host, "path", r.URL.Path,
				"method", r.Method, "subject", subject, "ingress", match.Ingress)
			http.Error(w, "you may not access this", http.StatusForbidden)
		}
	})
}

// requireLogin answers a caller who has not logged in but might get through if
// they did.
//
// A browser is sent to the login; anything else is told to authenticate. The
// difference matters because a program handed a 302 to a login page follows it
// and reports whatever HTML comes back as though it were the answer (ADR 0002).
func (a *Authorization) requireLogin(w http.ResponseWriter, r *http.Request) {
	log := a.Log.V(1).WithValues("host", r.Host, "path", r.URL.Path, "method", r.Method)

	if !WantsHTML(r.Header.Get("Accept")) {
		log.Info("challenged for credentials")
		challenge(w)
		return
	}
	if a.AuthHost == "" {
		// Refusing to start without --auth-host is the configuration's
		// job; if it is somehow empty there is nowhere to send anybody.
		a.Log.Info("a caller could log in, but no central authentication host is configured",
			"host", r.Host, "path", r.URL.Path)
		challenge(w)
		return
	}
	if routing.CanonicalHost(r.Host) == routing.CanonicalHost(a.AuthHost) {
		// The login lives on this host. Sending it to itself would be
		// a loop the browser eventually gives up on, with nothing said
		// about why.
		a.Log.Info("the central authentication host is itself protected", "host", r.Host)
		challenge(w)
		return
	}

	log.Info("sent to log in")
	// The answer depends on who is asking, and a cached login redirect
	// would be served to somebody who is already logged in.
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, a.loginURL(r), http.StatusFound)
}

// challenge answers a client that cannot be redirected.
func challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", authenticateRealm)
	http.Error(w, "you must authenticate to access this", http.StatusUnauthorized)
}

// loginURL is where a browser is sent, carrying the address to come back to.
//
// The address is absolute and always https: the plain listener forwards
// nothing to a backend (ADR 0013), so the only way back to a protected
// resource is over TLS. Whether that address may be returned to is checked on
// the way back, against the hosts the routing table knows, so that the
// parameter cannot be used to bounce a visitor off gated to somewhere else.
func (a *Authorization) loginURL(r *http.Request) string {
	next := (&url.URL{Scheme: "https", Host: r.Host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}).String()
	login := &url.URL{
		Scheme:   "https",
		Host:     a.AuthHost,
		Path:     LoginPath,
		RawQuery: url.Values{NextParam: []string{next}}.Encode(),
	}
	return login.String()
}

// WantsHTML reports whether an Accept header asks for something a person would
// read in a browser.
//
// Only a media range that names HTML counts. "*/*" does not: it is what curl
// and most client libraries send, and reading it as a browser would send every
// program that talks to a protected service to a login page it cannot use.
func WantsHTML(accept string) bool {
	for _, entry := range strings.Split(accept, ",") {
		mediaRange, parameters, _ := strings.Cut(entry, ";")
		mediaRange = strings.ToLower(strings.TrimSpace(mediaRange))
		switch mediaRange {
		case "text/html", "application/xhtml+xml", "text/*":
		default:
			continue
		}
		if quality(parameters) == "0" {
			// The client named HTML in order to refuse it.
			continue
		}
		return true
	}
	return false
}

// quality returns the q parameter of one media range, normalised enough to
// recognise a refusal. Anything that is not a refusal is treated as accepted:
// gated has one representation to offer and does not negotiate between several.
func quality(parameters string) string {
	for _, parameter := range strings.Split(parameters, ";") {
		name, value, found := strings.Cut(parameter, "=")
		if !found || strings.ToLower(strings.TrimSpace(name)) != "q" {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "0" || value == "0.0" || value == "0.00" || value == "0.000" {
			return "0"
		}
	}
	return ""
}

// subjectContextKey carries the principal to whatever runs after the
// middleware.
var subjectContextKey = &contextKey{"subject"}

// withSubject records who the decision was made about, so that the handlers
// after it do not resolve the identity a second time.
func withSubject(r *http.Request, subject string) *http.Request {
	if subject == "" {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), subjectContextKey, subject))
}

// SubjectFromContext returns the principal a request was authorised as, if it
// carried an identity at all.
func SubjectFromContext(ctx context.Context) (string, bool) {
	subject, ok := ctx.Value(subjectContextKey).(string)
	return subject, ok
}
