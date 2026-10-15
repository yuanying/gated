// Package proxy is gated's data plane: the two listeners, TLS termination and
// the reverse proxy that forwards a matched request to its backend.
//
// The routing table it works from is an immutable snapshot swapped in behind
// an atomic pointer (see TableStore). A request that has already been routed
// finishes against the table it was routed by, and no request handler ever
// holds a lock while talking to a backend.
package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"

	"github.com/yuanying/gated/internal/routing"
)

// TableStore holds the routing table currently in force.
//
// Rebuilding on every Ingress event and storing the result is cheap next to
// serving requests, so the read side never has to take a lock or copy
// anything. The zero value is usable and matches nothing until the first
// snapshot arrives.
type TableStore struct {
	table atomic.Pointer[routing.Table]
}

// Store puts a snapshot into force. In-flight requests keep using the table
// they started with.
func (s *TableStore) Store(t *routing.Table) {
	if s == nil {
		return
	}
	s.table.Store(t)
}

// Load returns the snapshot in force, or nil before the first one is stored.
// A nil table matches nothing, so callers do not need to check.
func (s *TableStore) Load() *routing.Table {
	if s == nil {
		return nil
	}
	return s.table.Load()
}

// HasHost reports whether any route claims this host. The login flow bounds
// the places it will return a visitor to with this, so that the address it is
// handed cannot be used to bounce somebody off gated to somewhere else.
func (s *TableStore) HasHost(host string) bool {
	return s.Load().HasHost(host)
}

// BackendResolver turns a routed backend into an address to dial.
//
// It is asked once per request and answers with one ready endpoint of the
// Service, not with its cluster IP (ADR 0033). A connection to a cluster IP is
// pinned to whichever Pod kube-proxy chose when it was opened, and a pooled one
// goes on being used after that Pod stops being ready. Dialling the endpoint
// itself keys the pool by Pod, so a Pod that is no longer chosen has its
// connections left alone too.
type BackendResolver interface {
	Resolve(ctx context.Context, backend routing.Backend) (string, error)
}

// Asserter vouches for the subject of a request on its way to a backend
// (ADR 0034).
//
// It is an interface because what it signs with lives in a Secret every
// replica reads for itself, and this package knows nothing about that.
type Asserter interface {
	// Assert returns the value of the assertion header for a request to
	// host made by subject.
	Assert(ctx context.Context, subject, host string) (string, error)
}

// The header gated vouches for a subject in, and the prefix it reserves for the
// headers it sets itself. They are spelled here rather than taken from the
// package that signs, because what this package must never get wrong is the
// stripping, and that needs no signer at all.
const (
	gatedHeaderPrefix = "gated-"
	assertionHeader   = "Gated-Assertion"
)

// ErrNoReadyEndpoints is what a BackendResolver wraps when the Service is there
// but nothing behind it can take a request. It is answered with 503 rather
// than 502: nothing was forwarded, and it may well pass (ADR 0033).
var ErrNoReadyEndpoints = errors.New("no ready endpoint")

// Handler routes a request and forwards it.
type Handler struct {
	// Tables is the snapshot to route against.
	Tables *TableStore
	// Backends turns the matched backend into an address.
	Backends BackendResolver
	// Transport is used for the outbound request. A nil Transport uses
	// the one gated builds for itself (ADR 0013), which is not
	// http.DefaultTransport.
	Transport http.RoundTripper
	// Assertions vouches for the subject of every request that has one. A
	// nil Asserter vouches for nobody; the client's own Gated- headers are
	// taken off either way.
	Assertions Asserter
	// BodyReadTimeout bounds one read of the client's request body, and
	// is renewed before each read: it is the gap between two reads that is
	// bounded, not the transfer. Zero uses the value in ADR 0030.
	BodyReadTimeout time.Duration
	// ResponseWriteTimeout bounds one write to the client, and is renewed
	// before each write: it is a client that stops reading that it ends,
	// not a response that is slow to produce. Zero uses the value in
	// ADR 0030.
	ResponseWriteTimeout time.Duration
	// Middleware wraps the forwarding step. The route has already been
	// resolved by the time it runs, so authentication and authorisation can
	// read it from the request context. A nil Middleware forwards directly.
	Middleware func(next http.Handler) http.Handler
	// Log receives the reasons requests failed. The zero Logger discards.
	Log logr.Logger

	once  sync.Once
	chain http.Handler
	proxy *httputil.ReverseProxy
}

// contextKey keeps the values this package puts on a request context from
// colliding with anybody else's.
type contextKey struct{ name string }

var (
	matchContextKey     = &contextKey{"routing-match"}
	targetContextKey    = &contextKey{"backend-target"}
	assertionContextKey = &contextKey{"assertion"}
)

// RequestWithMatch records the route a request was matched to, so that the
// middleware after routing — authorisation, and the login flow beside it — can
// read it without matching a second time.
func RequestWithMatch(r *http.Request, match routing.Match) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), matchContextKey, match))
}

// MatchFromContext returns the route a request was matched to, if it has been
// routed yet.
func MatchFromContext(ctx context.Context) (routing.Match, bool) {
	m, ok := ctx.Value(matchContextKey).(routing.Match)
	return m, ok
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Before anything reads the path: a path that gated and the backend
	// would resolve differently is refused rather than routed, because
	// authorisation compares it as a string and would be reading the
	// wrong one (ADR 0012).
	if err := routing.CheckPath(r.URL.Path, r.URL.RawPath); err != nil {
		h.Log.V(1).Info("refusing a path that is not in canonical form", "host", r.Host)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	match, ok := h.Tables.Load().Match(r.Host, r.URL.Path)
	if !ok {
		// Nothing claims this host and path, including before the first
		// snapshot has been installed.
		http.NotFound(w, r)
		return
	}

	h.init()
	h.chain.ServeHTTP(w, RequestWithMatch(r, match))
}

// init builds the handler chain and the reverse proxy once, so that the
// outbound connection pool is shared across every request.
func (h *Handler) init() {
	h.once.Do(func() {
		transport := h.Transport
		if transport == nil {
			transport = newTransport()
		}
		h.proxy = &httputil.ReverseProxy{
			Rewrite:      rewrite,
			Transport:    transport,
			ErrorHandler: h.handleUpstreamError,
			BufferPool:   newBufferPool(),
		}
		forward := h.guardDeadlines(http.HandlerFunc(h.forward))
		if h.Middleware != nil {
			h.chain = h.Middleware(forward)
			return
		}
		h.chain = forward
	})
}

// forward resolves the matched backend to an address and hands the request to
// the reverse proxy.
func (h *Handler) forward(w http.ResponseWriter, r *http.Request) {
	match, ok := MatchFromContext(r.Context())
	if !ok {
		http.NotFound(w, r)
		return
	}

	addr, err := h.Backends.Resolve(r.Context(), match.Backend)
	if errors.Is(err, ErrNoReadyEndpoints) {
		h.Log.Error(err, "no endpoint is ready to take the request",
			"host", r.Host, "path", r.URL.Path,
			"namespace", match.Backend.Namespace, "service", match.Backend.Service)
		http.Error(w, "the service behind this name has nothing ready to answer", http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		h.Log.Error(err, "resolving the backend",
			"host", r.Host, "path", r.URL.Path,
			"namespace", match.Backend.Namespace, "service", match.Backend.Service)
		http.Error(w, "the service behind this name cannot be resolved", http.StatusBadGateway)
		return
	}
	ctx := r.Context()
	if subject, ok := SubjectFromContext(ctx); ok && h.Assertions != nil {
		signed, err := h.Assertions.Assert(ctx, subject, r.Host)
		if err != nil {
			// Forwarding without it would tell the backend this
			// subject is anonymous. Better that the request is
			// refused for the moment it takes to read the key.
			h.Log.Error(err, "could not vouch for the subject of a request", "host", r.Host)
			http.Error(w, "this request cannot be passed on just now; try again", http.StatusServiceUnavailable)
			return
		}
		ctx = context.WithValue(ctx, assertionContextKey, signed)
	}

	if seen, ok := ctx.Value(observationKey).(*observation); ok {
		seen.upstream = addr
	}

	target := &url.URL{Scheme: "http", Host: addr}
	h.proxy.ServeHTTP(w, r.WithContext(context.WithValue(ctx, targetContextKey, target)))
}

// handleUpstreamError turns a failed outbound request into a 502. A client
// that went away is not an upstream failure and gets no response at all.
func (h *Handler) handleUpstreamError(w http.ResponseWriter, r *http.Request, err error) {
	// A body that stopped arriving takes its connection down with it, and
	// the forwarded request then fails as a cancellation. Without saying so
	// here, the client would be answered 200 for a request whose body never
	// reached the backend.
	if state, ok := transferFromContext(r.Context()); ok && state.bodyTimedOut.Load() {
		h.Log.V(1).Info("the client stopped sending its request body", "host", r.Host)
		http.Error(w, "the request body stopped arriving", http.StatusRequestTimeout)
		return
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	h.Log.Error(err, "forwarding the request", "host", r.Host, "path", r.URL.Path)
	http.Error(w, "the service behind this name is not answering", http.StatusBadGateway)
}

// rewrite prepares the outbound request.
//
// Using Rewrite rather than Director is what makes the forwarded headers
// trustworthy: it drops whatever the client claimed about being forwarded, and
// SetXForwarded then states what gated itself observed. gated sits at the
// edge, so a client-supplied X-Forwarded-For is a claim about its own address
// and must not be carried through.
func rewrite(pr *httputil.ProxyRequest) {
	target, _ := pr.In.Context().Value(targetContextKey).(*url.URL)
	if target != nil {
		pr.SetURL(target)
	}
	// Applications that build absolute links, and anything that virtual-hosts
	// on the Host header, need the name the client asked for.
	pr.Out.Host = pr.In.Host
	pr.SetXForwarded()
	setRealIP(pr.Out)
	dropGatedCookies(pr.Out)
	dropGatedHeaders(pr.Out)
	if signed, ok := pr.In.Context().Value(assertionContextKey).(string); ok {
		pr.Out.Header.Set(assertionHeader, signed)
	}
}

// dropGatedHeaders takes off every header a client sent under gated's prefix,
// so that behind gated a Gated- header is always one gated wrote (ADR 0034).
//
// The whole prefix goes rather than a list of names. A header gated starts to
// set later is then protected from the day it is added, instead of from the day
// somebody remembers to add it to the list.
func dropGatedHeaders(out *http.Request) {
	for name := range out.Header {
		if len(name) >= len(gatedHeaderPrefix) && strings.EqualFold(name[:len(gatedHeaderPrefix)], gatedHeaderPrefix) {
			delete(out.Header, name)
		}
	}
}

// setRealIP states the one address gated observed, under the name
// ingress-nginx used for it (ADR 0013).
//
// SetXForwarded has just replaced X-Forwarded-For with that address and
// nothing else, so it is the value to copy. When it could not — an address it
// could not parse — there is nothing to say, and the client's own claim to the
// header goes with it.
func setRealIP(out *http.Request) {
	if ip := out.Header.Get("X-Forwarded-For"); ip != "" {
		out.Header.Set("X-Real-IP", ip)
		return
	}
	out.Header.Del("X-Real-IP")
}

// dropGatedCookies takes gated's own cookies out of the request on its way to
// a backend, and leaves every other cookie exactly as it arrived (ADR 0013).
func dropGatedCookies(out *http.Request) {
	values := out.Header["Cookie"]
	kept := make([]string, 0, len(values))
	for _, value := range values {
		// The common request carries none of them, and is left
		// untouched rather than taken apart and put back together.
		if !strings.Contains(value, gatedCookiePrefix) {
			kept = append(kept, value)
			continue
		}
		if remaining := withoutGatedCookies(value); remaining != "" {
			kept = append(kept, remaining)
		}
	}
	if len(kept) == 0 {
		out.Header.Del("Cookie")
		return
	}
	out.Header["Cookie"] = kept
}

// withoutGatedCookies returns one Cookie header value with gated's own cookies
// removed, keeping the rest in the order they arrived.
func withoutGatedCookies(value string) string {
	var kept strings.Builder
	for part := range strings.SplitSeq(value, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, _, _ := strings.Cut(part, "=")
		if isGatedCookie(name) {
			continue
		}
		if kept.Len() > 0 {
			kept.WriteString("; ")
		}
		kept.WriteString(part)
	}
	return kept.String()
}

// isGatedCookie reports whether a cookie belongs to gated rather than to the
// application behind it.
func isGatedCookie(name string) bool {
	switch name {
	case SessionCookieName, LoginCookieName, StateCookieName:
		return true
	}
	return false
}
