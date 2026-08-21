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
	"sync"
	"sync/atomic"

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

// BackendResolver turns a routed backend into an address to dial.
//
// gated forwards to the Service's cluster IP and lets kube-proxy pick an
// endpoint (ADR 0001): reproducing endpoint selection here would mean tracking
// EndpointSlices, readiness and topology for no gain.
type BackendResolver interface {
	Resolve(ctx context.Context, backend routing.Backend) (string, error)
}

// Handler routes a request and forwards it.
type Handler struct {
	// Tables is the snapshot to route against.
	Tables *TableStore
	// Backends turns the matched backend into an address.
	Backends BackendResolver
	// Transport is used for the outbound request. A nil Transport uses
	// http.DefaultTransport.
	Transport http.RoundTripper
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
	matchContextKey  = &contextKey{"routing-match"}
	targetContextKey = &contextKey{"backend-target"}
)

// MatchFromContext returns the route a request was matched to, if it has been
// routed yet.
func MatchFromContext(ctx context.Context) (routing.Match, bool) {
	m, ok := ctx.Value(matchContextKey).(routing.Match)
	return m, ok
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	match, ok := h.Tables.Load().Match(r.Host, r.URL.Path)
	if !ok {
		// Nothing claims this host and path, including before the first
		// snapshot has been installed.
		http.NotFound(w, r)
		return
	}

	h.init()
	h.chain.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), matchContextKey, match)))
}

// init builds the handler chain and the reverse proxy once, so that the
// outbound connection pool is shared across every request.
func (h *Handler) init() {
	h.once.Do(func() {
		h.proxy = &httputil.ReverseProxy{
			Rewrite:      rewrite,
			Transport:    h.Transport,
			ErrorHandler: h.handleUpstreamError,
		}
		forward := http.HandlerFunc(h.forward)
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
	if err != nil {
		h.Log.Error(err, "resolving the backend",
			"host", r.Host, "path", r.URL.Path,
			"namespace", match.Backend.Namespace, "service", match.Backend.Service)
		http.Error(w, "the service behind this name cannot be resolved", http.StatusBadGateway)
		return
	}

	target := &url.URL{Scheme: "http", Host: addr}
	h.proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), targetContextKey, target)))
}

// handleUpstreamError turns a failed outbound request into a 502. A client
// that went away is not an upstream failure and gets no response at all.
func (h *Handler) handleUpstreamError(w http.ResponseWriter, r *http.Request, err error) {
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
}
