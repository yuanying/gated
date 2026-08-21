package proxy

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-logr/logr"

	"github.com/yuanying/gated/internal/routing"
)

// ChallengePath is the prefix ACME reserves for HTTP-01 validation. Requests
// under it are answered by gated itself and never reach a backend (ADR 0005).
const ChallengePath = "/.well-known/acme-challenge/"

// ChallengeSolver answers one HTTP-01 challenge.
//
// Every replica must be able to answer, not only the one that ordered the
// certificate, because the validation server picks whichever replica the load
// balancer hands it (ADR 0006). The implementation therefore reads the
// challenge from a shared Secret rather than from process memory.
type ChallengeSolver interface {
	KeyAuthorization(ctx context.Context, host, token string) (string, bool)
}

// InsecureHandler serves the plain HTTP listener.
//
// It has exactly two jobs: answer ACME challenges, and send everything else to
// HTTPS. Nothing on this listener is proxied, so an unencrypted request can
// never reach a backend.
type InsecureHandler struct {
	// Solver answers HTTP-01 challenges. Until certificate issuance is
	// wired up there is none, and challenges are simply not found.
	Solver ChallengeSolver
	// Log receives the reasons requests failed. The zero Logger discards.
	Log logr.Logger
}

func (h *InsecureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := routing.CanonicalHost(r.Host)
	if host == "" {
		http.Error(w, "the request names no host", http.StatusBadRequest)
		return
	}

	if token, ok := strings.CutPrefix(r.URL.Path, ChallengePath); ok {
		h.serveChallenge(w, r, host, token)
		return
	}

	target := "https://" + host + r.URL.RequestURI()
	// 308 keeps the method and the body. A 301 would turn a POST into a GET,
	// which is a silent way to lose a request.
	http.Redirect(w, r, target, http.StatusPermanentRedirect)
}

// serveChallenge answers a validation request, or reports that this token is
// not one gated is expecting.
//
// A miss is a 404 and never a redirect: redirecting the validation server to
// HTTPS would send it to a host whose certificate is precisely what the
// challenge is trying to obtain.
func (h *InsecureHandler) serveChallenge(w http.ResponseWriter, r *http.Request, host, token string) {
	if h.Solver == nil || token == "" {
		http.NotFound(w, r)
		return
	}
	keyAuth, ok := h.Solver.KeyAuthorization(r.Context(), host, token)
	if !ok {
		h.Log.V(1).Info("no such ACME challenge", "host", host)
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(keyAuth))
}
