package authn

import (
	"net/http"

	"github.com/yuanying/gated/internal/routing"
)

// Router puts the login in front of the data plane.
//
// The paths it claims are answered by gated itself and never routed, never
// authorised and never forwarded (ADR 0018). That is what keeps the login from
// needing a login, and what lets the central authentication host answer even
// though no Ingress points anywhere for it.
type Router struct {
	// AuthHost is the central authentication host. Required.
	AuthHost string
	// Central answers the login flow on that host. Required.
	Central http.Handler
	// Callback answers the last leg on a protected host. Required.
	Callback http.Handler
	// Next is everything else: routing, authorisation, the proxy.
	Next http.Handler
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if routing.CanonicalHost(req.Host) == routing.CanonicalHost(r.AuthHost) {
		// The reserved prefix belongs to the login here. Everything
		// else on this host is an ordinary route, so a central host
		// that also serves something keeps serving it.
		if len(req.URL.Path) >= len(ReservedPrefix) && req.URL.Path[:len(ReservedPrefix)] == ReservedPrefix {
			r.Central.ServeHTTP(w, req)
			return
		}
	} else if req.URL.Path == CallbackPath {
		r.Callback.ServeHTTP(w, req)
		return
	}
	r.Next.ServeHTTP(w, req)
}
