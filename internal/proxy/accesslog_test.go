package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/yuanying/gated/internal/routing"
)

// logLine is one record the access log wrote.
type logLine struct {
	msg    string
	values map[string]any
}

// recordingSink keeps what was logged, so that a test can assert on the fields
// of a line rather than on its rendering.
type recordingSink struct {
	mu    sync.Mutex
	lines []logLine
}

func (s *recordingSink) Init(logr.RuntimeInfo)                {}
func (s *recordingSink) Enabled(int) bool                     { return true }
func (s *recordingSink) WithName(string) logr.LogSink         { return s }
func (s *recordingSink) WithValues(...any) logr.LogSink       { return s }
func (s *recordingSink) Error(_ error, msg string, kv ...any) { s.Info(0, msg, kv...) }

func (s *recordingSink) Info(_ int, msg string, kv ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	values := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok {
			continue
		}
		values[key] = kv[i+1]
	}
	s.lines = append(s.lines, logLine{msg: msg, values: values})
}

func (s *recordingSink) written() []logLine {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]logLine(nil), s.lines...)
}

// only returns the single line the log wrote, waiting for it: the line is
// written when the handler returns, which for a hijacked connection is after
// the client has already read the response.
func (s *recordingSink) only(t *testing.T) logLine {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		lines := s.written()
		switch {
		case len(lines) == 1:
			return lines[0]
		case len(lines) > 1:
			t.Fatalf("the access log wrote %d lines, want exactly one: %v", len(lines), lines)
		case time.Now().After(deadline):
			t.Fatal("the access log wrote nothing")
		}
		time.Sleep(time.Millisecond)
	}
}

// newAccessLog wires a log with somewhere to write and somewhere to count.
func newAccessLog(next http.Handler) (http.Handler, *recordingSink, *prometheus.Registry) {
	sink := &recordingSink{}
	registry := prometheus.NewPedanticRegistry()
	log := &AccessLog{
		Log:     logr.New(sink),
		Metrics: NewHTTPMetrics(registry),
	}
	return log.Wrap(next), sink, registry
}

// sendGet sends one request through a wrapped handler.
func sendGet(t *testing.T, h http.Handler, target string, decorate func(*http.Request)) *http.Response {
	t.Helper()

	server := httptest.NewServer(h)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+target, nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	if decorate != nil {
		decorate(req)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("sending the request: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	io.Copy(io.Discard, resp.Body)
	return resp
}

// A request that arrives is a line, and the line says what happened to it.
func TestAccessLogWritesOneLinePerRequest(t *testing.T) {
	handler, sink, _ := newAccessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		io.WriteString(w, "hello")
	}))
	sendGet(t, handler, "/a/b", func(r *http.Request) { r.Host = "app.example.com" })

	got := sink.only(t)
	for key, want := range map[string]any{
		"method": http.MethodGet,
		"host":   "app.example.com",
		"path":   "/a/b",
		"status": http.StatusTeapot,
		"bytes":  int64(len("hello")),
		"proto":  "HTTP/1.1",
	} {
		if got.values[key] != want {
			t.Errorf("line[%q] = %v (%T), want %v", key, got.values[key], got.values[key], want)
		}
	}
	if client, _ := got.values["client"].(string); client == "" || strings.Contains(client, ":") {
		t.Errorf("line[client] = %q, want the host part of the remote address on its own", client)
	}
	if _, ok := got.values["duration"]; !ok {
		t.Error("the line carries no duration")
	}
}

// The query string carries the one-time token a completed login hands to the
// browser, and the two headers are credentials as they stand (ADR 0031).
func TestAccessLogWritesNoCredentials(t *testing.T) {
	handler, sink, _ := newAccessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	sendGet(t, handler, "/__gated/callback?t=handoff-token&next=/somewhere", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer bearer-token")
		r.AddCookie(&http.Cookie{Name: "__gated_session", Value: "session-cookie"})
	})

	got := sink.only(t)
	if got.values["path"] != "/__gated/callback" {
		t.Errorf("line[path] = %v, want the path without its query", got.values["path"])
	}
	for _, secret := range []string{"handoff-token", "bearer-token", "session-cookie", "t=", "Authorization", "Cookie"} {
		for key, value := range got.values {
			if rendered, ok := value.(string); ok && strings.Contains(rendered, secret) {
				t.Errorf("line[%q] = %q, which carries %q", key, rendered, secret)
			}
		}
	}
}

// Everything the line says about who was asking and what was matched is
// learned after the wrapper has already been entered, so the handlers inside
// hand it back through Observe.
func TestAccessLogRecordsTheRouteAndTheSubject(t *testing.T) {
	match := routing.Match{Ingress: routing.ResourceRef{Namespace: "apps", Name: "web"}}

	inner := Observe(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler, sink, registry := newAccessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner.ServeHTTP(w, withSubject(RequestWithMatch(r, match), "github:octocat"))
	}))
	sendGet(t, handler, "/", nil)

	got := sink.only(t)
	if got.values["ingress"] != match.Ingress {
		t.Errorf("line[ingress] = %v, want %v", got.values["ingress"], match.Ingress)
	}
	if got.values["subject"] != "github:octocat" {
		t.Errorf("line[subject] = %v, want the principal the decision named", got.values["subject"])
	}

	// The same route is what the counters are labelled by.
	const want = `
# HELP gated_http_requests_total Requests answered, by the Ingress that routed them.
# TYPE gated_http_requests_total counter
gated_http_requests_total{code="200",ingress_name="web",ingress_namespace="apps",method="GET"} 1
`
	if err := testutil.GatherAndCompare(registry, strings.NewReader(want), "gated_http_requests_total"); err != nil {
		t.Error(err)
	}
}

// A request nothing claims still counts. The labels are empty rather than
// absent, because a series that appears only sometimes is harder to read than
// one that is always there.
func TestAccessLogRecordsAnUnroutedRequest(t *testing.T) {
	handler, sink, registry := newAccessLog(http.NotFoundHandler())
	sendGet(t, handler, "/nothing", nil)

	got := sink.only(t)
	if got.values["ingress"] != (routing.ResourceRef{}) {
		t.Errorf("line[ingress] = %v, want the zero reference", got.values["ingress"])
	}
	if got.values["subject"] != "" {
		t.Errorf("line[subject] = %v, want an empty subject", got.values["subject"])
	}
	if got.values["status"] != http.StatusNotFound {
		t.Errorf("line[status] = %v, want %d", got.values["status"], http.StatusNotFound)
	}
	const want = `
# HELP gated_http_requests_total Requests answered, by the Ingress that routed them.
# TYPE gated_http_requests_total counter
gated_http_requests_total{code="404",ingress_name="",ingress_namespace="",method="GET"} 1
`
	if err := testutil.GatherAndCompare(registry, strings.NewReader(want), "gated_http_requests_total"); err != nil {
		t.Error(err)
	}
}

// A handler that writes a body without saying anything about the status has
// answered 200, and the line has to say what the client saw.
func TestAccessLogReportsAnImpliedStatus(t *testing.T) {
	handler, sink, _ := newAccessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "body")
	}))
	sendGet(t, handler, "/", nil)

	if got := sink.only(t); got.values["status"] != http.StatusOK {
		t.Errorf("line[status] = %v, want %d", got.values["status"], http.StatusOK)
	}
}

// 502 is the one status that says the request could not be delivered rather
// than that it was refused.
func TestAccessLogCountsUpstreamErrors(t *testing.T) {
	handler, sink, registry := newAccessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "the service behind this name is not answering", http.StatusBadGateway)
	}))
	sendGet(t, handler, "/", nil)

	if got := sink.only(t); got.values["upstreamError"] != true {
		t.Errorf("line[upstreamError] = %v, want true", got.values["upstreamError"])
	}
	const want = `
# HELP gated_upstream_errors_total Requests that ended in a 502, by the Ingress that routed them.
# TYPE gated_upstream_errors_total counter
gated_upstream_errors_total{ingress_name="",ingress_namespace=""} 1
`
	if err := testutil.GatherAndCompare(registry, strings.NewReader(want), "gated_upstream_errors_total"); err != nil {
		t.Error(err)
	}
}

// Anything else leaves the counter alone.
func TestAccessLogCountsNoUpstreamErrorForARefusal(t *testing.T) {
	handler, _, registry := newAccessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "you may not access this", http.StatusForbidden)
	}))
	sendGet(t, handler, "/", nil)

	if got := testutil.CollectAndCount(registry, "gated_upstream_errors_total"); got != 0 {
		t.Errorf("gated_upstream_errors_total has %d series, want none", got)
	}
}

// An upgraded connection leaves through the hijacker, so the wrapper has to be
// on the path that takes it: the status the client saw is 101, and what
// crosses the connection afterwards is not gated's to count.
func TestAccessLogFollowsAnUpgrade(t *testing.T) {
	handler, sink, _ := newAccessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("Hijack() = %v, want it to reach the server's own writer", err)
			return
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		buf.Flush()
	}))

	server := httptest.NewServer(handler)
	defer server.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET /socket HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		t.Fatalf("reading the status line: %v", err)
	}

	got := sink.only(t)
	if got.values["status"] != http.StatusSwitchingProtocols {
		t.Errorf("line[status] = %v, want %d", got.values["status"], http.StatusSwitchingProtocols)
	}
	if got.values["proto"] != "ws" {
		t.Errorf("line[proto] = %v, want %q", got.values["proto"], "ws")
	}
}

// The wrapper sits between the server and a reverse proxy that streams, so
// every capability the writer underneath has must still be reachable through
// it.
func TestAccessLogLetsFlushThrough(t *testing.T) {
	flushed := make(chan struct{})
	handler, _, _ := newAccessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: one\n\n")
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("Flush() = %v, want it to reach the server's own writer", err)
		}
		close(flushed)
	}))

	server := httptest.NewServer(handler)
	defer server.Close()
	resp, err := server.Client().Get(server.URL + "/stream")
	if err != nil {
		t.Fatalf("sending the request: %v", err)
	}
	defer resp.Body.Close()
	<-flushed
	if _, err := bufio.NewReader(resp.Body).ReadString('\n'); err != nil {
		t.Fatalf("reading the first chunk: %v", err)
	}
}

// Switching the log off is not switching the measurement off: the two answer
// different questions (ADR 0031).
func TestAccessLogWithoutALoggerStillCounts(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	log := &AccessLog{Metrics: NewHTTPMetrics(registry)}
	sendGet(t, log.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})), "/", nil)

	if got := testutil.CollectAndCount(registry, "gated_http_requests_total"); got != 1 {
		t.Errorf("gated_http_requests_total has %d series, want 1", got)
	}
	if got := testutil.CollectAndCount(registry, "gated_http_request_duration_seconds"); got != 1 {
		t.Errorf("gated_http_request_duration_seconds has %d series, want 1", got)
	}
}

// A log with nothing to count and nothing to write to must still serve.
func TestAccessLogZeroValueServes(t *testing.T) {
	log := &AccessLog{}
	resp := sendGet(t, log.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})), "/", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}
