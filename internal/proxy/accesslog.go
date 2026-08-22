package proxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"time"

	"github.com/go-logr/logr"

	"github.com/yuanying/gated/internal/routing"
)

// AccessLog records what passed through the edge: one line per request, and
// the counters beside it (ADR 0031).
//
// It wraps everything, the login flow included, so that the paths gated
// answers itself are recorded too. What it writes is bounded on purpose. The
// query string carries the one-time token a completed login hands to the
// browser (ADR 0003), and the Authorization and Cookie headers are
// credentials as they stand, so none of the three is ever written.
type AccessLog struct {
	// Log receives one Info line per request. The zero Logger discards,
	// which is what --access-log=false leaves behind; the counters below
	// are unaffected by that, because "what is happening now" and "who
	// asked for what" are different questions.
	Log logr.Logger
	// Metrics counts every request. A nil Metrics counts nothing.
	Metrics *HTTPMetrics
	// Now reads the clock, overridable in tests.
	Now func() time.Time
}

// observation is what a request turns out to have been, filled in as it goes.
//
// The route and the principal are settled well inside the handler chain, on
// contexts derived from the one this wrapper made. A derived context cannot be
// read from out here, so the wrapper puts a mutable record on the way in and
// Observe copies into it on the way past. Everything is written and read on
// the goroutine serving the request.
type observation struct {
	ingress routing.ResourceRef
	subject string
}

var observationKey = &contextKey{"access-log-observation"}

// Observe returns a handler that copies what the request has learned so far —
// the Ingress it was routed to, the principal it was authorised as — into the
// record the access log is keeping for it.
//
// It is placed at the points where those become known rather than being asked
// for them afterwards, because each of them lives on a context the caller
// cannot see.
func Observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen, ok := r.Context().Value(observationKey).(*observation); ok {
			if match, routed := MatchFromContext(r.Context()); routed {
				seen.ingress = match.Ingress
			}
			if subject, named := SubjectFromContext(r.Context()); named {
				seen.subject = subject
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Wrap returns a handler that records what next did with each request.
func (a *AccessLog) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen := &observation{}
		recorder := &recordingWriter{ResponseWriter: w}
		started := a.now()

		next.ServeHTTP(recorder, r.WithContext(context.WithValue(r.Context(), observationKey, seen)))

		elapsed := a.now().Sub(started)
		status := recorder.result()
		upstreamError := status == http.StatusBadGateway

		a.Metrics.observe(seen.ingress, r.Method, status, elapsed, upstreamError)
		a.Log.Info("request",
			"client", clientOf(r),
			"method", r.Method,
			"host", r.Host,
			// Without its query: see the type's own comment.
			"path", r.URL.Path,
			"status", status,
			"bytes", recorder.written,
			"duration", elapsed,
			"subject", seen.subject,
			"ingress", seen.ingress,
			"proto", protocolOf(r, recorder.hijacked),
			"upstreamError", upstreamError,
		)
	})
}

func (a *AccessLog) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// clientOf is the address gated was reached from, without its port.
//
// It is whoever opened the connection, which is the client itself only when
// nothing in front of gated rewrites the source address. gated does not
// correct it from what the request claims: a client's own account of where it
// is coming from is not evidence (ADR 0013).
func clientOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// protocolOf names the protocol the answer left over. An upgraded connection
// stops being HTTP at the point it is hijacked, and saying "HTTP/1.1" about a
// socket that carried frames for an hour reads as though it were a request
// that took an hour.
func protocolOf(r *http.Request, hijacked bool) string {
	if hijacked {
		return "ws"
	}
	return r.Proto
}

// recordingWriter remembers what the response turned out to be.
//
// It has to stay transparent. Another wrapper sits inside this one and a
// reverse proxy that streams and upgrades sits inside that, so Flush and
// Hijack have to reach the server's own writer through both: Unwrap is what
// lets http.ResponseController find them, and Hijack is implemented here only
// so that an upgrade is noticed on the way past.
type recordingWriter struct {
	http.ResponseWriter

	status   int
	written  int64
	hijacked bool
}

// Unwrap gives http.ResponseController the writer underneath.
func (w *recordingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *recordingWriter) WriteHeader(status int) {
	// 1xx is an interim answer: the server may send several, and the one
	// that ends the request comes after them.
	if status >= http.StatusOK && w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *recordingWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.written += int64(n)
	return n, err
}

func (w *recordingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, buffered, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil {
		w.hijacked = true
	}
	return conn, buffered, err
}

// result is the status the client saw.
//
// A handler that wrote nothing at all has answered 200, because that is what
// the server sends for it. A hijacked connection has answered whatever gated
// wrote onto the socket, and every upgrade gated forwards is a 101.
func (w *recordingWriter) result() int {
	switch {
	case w.hijacked:
		return http.StatusSwitchingProtocols
	case w.status == 0:
		return http.StatusOK
	default:
		return w.status
	}
}
