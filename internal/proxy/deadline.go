package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

// How long a single read of a client's body, and a single write to a client,
// may take (ADR 0030).
//
// Both are deadlines on one operation and not on the transfer: they are
// renewed immediately before each read and each write. A body that keeps
// arriving may take as long as it likes, and a response that has nothing to
// say for an hour is not writing and so is not being timed. What they end is
// the client that stops sending mid-body, and the client that stops reading.
const (
	defaultBodyReadTimeout      = 60 * time.Second
	defaultResponseWriteTimeout = 60 * time.Second
)

func (h *Handler) bodyReadTimeout() time.Duration {
	if h.BodyReadTimeout > 0 {
		return h.BodyReadTimeout
	}
	return defaultBodyReadTimeout
}

func (h *Handler) responseWriteTimeout() time.Duration {
	if h.ResponseWriteTimeout > 0 {
		return h.ResponseWriteTimeout
	}
	return defaultResponseWriteTimeout
}

// guardDeadlines puts the request body and the response writer behind the
// deadlines above, for the duration of the forwarding step.
//
// It sits immediately in front of the reverse proxy rather than at the edge of
// the handler chain: what needs bounding is the transfer, and everything gated
// answers by itself is written and gone before it could be slow.
func (h *Handler) guardDeadlines(next http.Handler) http.Handler {
	read, write := h.bodyReadTimeout(), h.responseWriteTimeout()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		guarded := &deadlineWriter{ResponseWriter: w, rc: rc, timeout: write}
		if r.Body != nil && r.Body != http.NoBody {
			state := &transfer{}
			r = r.WithContext(context.WithValue(r.Context(), transferContextKey, state))
			r.Body = &deadlineBody{ReadCloser: r.Body, rc: rc, timeout: read, state: state}
		}
		// Leaving a deadline standing would make the connection's next
		// use fail against a limit that was meant for this one.
		defer guarded.clear()
		next.ServeHTTP(guarded, r)
	})
}

// transfer carries what went wrong with the client's half of a transfer to the
// place that answers for it. A read that runs out of time takes the connection
// with it, and the request context is cancelled as a result, so by the time the
// forwarded request fails, the reason it failed no longer looks like anything
// the client did.
type transfer struct {
	bodyTimedOut atomic.Bool
}

// transferContextKey carries a *transfer. The reverse proxy clones the request
// but keeps its context, so what the body records is readable from the error
// handler.
var transferContextKey = &contextKey{"transfer-state"}

// transferFromContext returns what has gone wrong with this transfer so far.
func transferFromContext(ctx context.Context) (*transfer, bool) {
	t, ok := ctx.Value(transferContextKey).(*transfer)
	return t, ok
}

// deadlineBody renews the read deadline before every read of a client's body.
type deadlineBody struct {
	io.ReadCloser
	rc      *http.ResponseController
	timeout time.Duration
	state   *transfer
}

func (b *deadlineBody) Read(p []byte) (int, error) {
	// The error is what a ResponseWriter that cannot take deadlines
	// returns. There is nothing to do about it here, and the transfer is
	// not made worse by being unbounded.
	_ = b.rc.SetReadDeadline(time.Now().Add(b.timeout))
	n, err := b.ReadCloser.Read(p)
	if err != nil && errors.Is(err, os.ErrDeadlineExceeded) {
		b.state.bodyTimedOut.Store(true)
	}
	return n, err
}

// deadlineWriter renews the write deadline before every write to a client.
//
// It passes Flush and Hijack through, which is what keeps streaming and
// protocol upgrades working: the reverse proxy reaches both through
// http.ResponseController, and an access log wrapping this one reaches them
// the same way (Unwrap).
type deadlineWriter struct {
	http.ResponseWriter
	rc       *http.ResponseController
	timeout  time.Duration
	hijacked bool
}

// Unwrap gives http.ResponseController, and anything else that looks through
// wrappers, the writer underneath.
func (w *deadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *deadlineWriter) WriteHeader(code int) {
	w.extend()
	w.ResponseWriter.WriteHeader(code)
}

func (w *deadlineWriter) Write(p []byte) (int, error) {
	w.extend()
	return w.ResponseWriter.Write(p)
}

// FlushError is what http.ResponseController prefers over Flush, and the form
// that can report a client that has gone away: the reverse proxy stops copying
// a streamed response on that error.
func (w *deadlineWriter) FlushError() error {
	w.extend()
	return w.rc.Flush()
}

// Flush is here for callers that assert on http.Flusher directly rather than
// going through a controller.
func (w *deadlineWriter) Flush() { _ = w.FlushError() }

// Hijack hands over the connection, and takes the deadlines off it on the way
// out. After an upgrade the bytes no longer pass through this writer, so a
// deadline set before it would apply to a conversation nothing here is timing
// — an idle WebSocket would be cut at the first quiet minute (ADR 0030).
func (w *deadlineWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, buf, err := w.rc.Hijack()
	if err != nil {
		return nil, nil, err
	}
	w.hijacked = true
	_ = conn.SetDeadline(time.Time{})
	return conn, buf, nil
}

func (w *deadlineWriter) extend() {
	if w.hijacked {
		return
	}
	_ = w.rc.SetWriteDeadline(time.Now().Add(w.timeout))
}

// clear takes the deadlines off once the transfer is over. A hijacked
// connection has already had that done and no longer belongs to this request.
func (w *deadlineWriter) clear() {
	if w.hijacked {
		return
	}
	_ = w.rc.SetWriteDeadline(time.Time{})
	_ = w.rc.SetReadDeadline(time.Time{})
}
