package proxy_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/yuanying/gated/internal/proxy"
	"github.com/yuanying/gated/internal/routing"
)

// resolverFunc adapts a function to the BackendResolver interface.
type resolverFunc func(context.Context, routing.Backend) (string, error)

func (f resolverFunc) Resolve(ctx context.Context, b routing.Backend) (string, error) {
	return f(ctx, b)
}

// toAddress sends every backend to one address, which is all a test with a
// single upstream needs.
func toAddress(addr string) proxy.BackendResolver {
	return resolverFunc(func(context.Context, routing.Backend) (string, error) { return addr, nil })
}

// tableFor builds a store holding one route covering the whole host.
func tableFor(host string) *proxy.TableStore {
	store := &proxy.TableStore{}
	store.Store(routing.BuildTable([]routing.Ingress{{
		Namespace: "apps",
		Name:      "app",
		Rules: []routing.HostRule{{
			Host: host,
			Paths: []routing.PathRule{{
				Path:     "/",
				PathType: routing.PathTypePrefix,
				Backend:  routing.Backend{Namespace: "apps", Service: "web", PortNumber: 80},
			}},
		}},
	}}))
	return store
}

// addressOf returns the host:port an httptest server listens on.
func addressOf(t *testing.T, s *httptest.Server) string {
	t.Helper()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatalf("parsing %q: %v", s.URL, err)
	}
	return u.Host
}

func TestProxyForwardsToTheBackend(t *testing.T) {
	var got *http.Request
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		w.Header().Set("X-From", "backend")
		io.WriteString(w, "hello")
	}))
	defer backend.Close()

	front := httptest.NewServer(&proxy.Handler{
		Tables:   tableFor("app.example.com"),
		Backends: toAddress(addressOf(t, backend)),
	})
	defer front.Close()

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/some/path?q=1", nil)
	req.Host = "app.example.com"
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatalf("Do() = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Errorf("body = %q, want %q", body, "hello")
	}
	if resp.Header.Get("X-From") != "backend" {
		t.Errorf("X-From = %q, want %q", resp.Header.Get("X-From"), "backend")
	}
	if got == nil {
		t.Fatal("the backend was never reached")
	}
	if got.URL.RequestURI() != "/some/path?q=1" {
		t.Errorf("backend saw %q, want %q", got.URL.RequestURI(), "/some/path?q=1")
	}
	// The backend has to keep seeing the name the client asked for:
	// virtual-hosted applications and the absolute URLs they generate
	// depend on it.
	if got.Host != "app.example.com" {
		t.Errorf("backend saw Host %q, want %q", got.Host, "app.example.com")
	}
}

func TestProxySetsForwardedHeaders(t *testing.T) {
	var got http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}))
	defer backend.Close()

	front := httptest.NewServer(&proxy.Handler{
		Tables:   tableFor("app.example.com"),
		Backends: toAddress(addressOf(t, backend)),
	})
	defer front.Close()

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/", nil)
	req.Host = "app.example.com"
	// A client that claims to have been forwarded already. gated sits at the
	// edge, so this is a claim it must not believe.
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "evil.example.net")
	if _, err := front.Client().Do(req); err != nil {
		t.Fatalf("Do() = %v", err)
	}

	if got.Get("X-Forwarded-Host") != "app.example.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q", got.Get("X-Forwarded-Host"), "app.example.com")
	}
	if got.Get("X-Forwarded-Proto") != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", got.Get("X-Forwarded-Proto"), "http")
	}
	xff := got.Get("X-Forwarded-For")
	if strings.Contains(xff, "203.0.113.9") {
		t.Errorf("X-Forwarded-For = %q, want the client-supplied value discarded", xff)
	}
	if xff == "" {
		t.Error("X-Forwarded-For is empty, want the peer address")
	}
}

func TestProxyStripsHopByHopHeaders(t *testing.T) {
	var got http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		// A hop-by-hop header on the way back must not reach the client
		// either.
		w.Header().Set("Connection", "X-Backend-Private")
		w.Header().Set("X-Backend-Private", "secret")
		w.Header().Set("Keep-Alive", "timeout=5")
	}))
	defer backend.Close()

	front := httptest.NewServer(&proxy.Handler{
		Tables:   tableFor("app.example.com"),
		Backends: toAddress(addressOf(t, backend)),
	})
	defer front.Close()

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/", nil)
	req.Host = "app.example.com"
	req.Header.Set("X-Client-Private", "value")
	req.Header.Set("Connection", "X-Client-Private")
	req.Header.Set("Te", "trailers, deflate")
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatalf("Do() = %v", err)
	}
	defer resp.Body.Close()

	if v := got.Get("X-Client-Private"); v != "" {
		t.Errorf("backend saw X-Client-Private = %q, want it dropped as hop-by-hop", v)
	}
	if v := got.Get("Connection"); v != "" {
		t.Errorf("backend saw Connection = %q, want it dropped", v)
	}
	if v := resp.Header.Get("X-Backend-Private"); v != "" {
		t.Errorf("client saw X-Backend-Private = %q, want it dropped as hop-by-hop", v)
	}
	if v := resp.Header.Get("Keep-Alive"); v != "" {
		t.Errorf("client saw Keep-Alive = %q, want it dropped", v)
	}
}

func TestProxyReturnsNotFoundWithoutARoute(t *testing.T) {
	front := httptest.NewServer(&proxy.Handler{
		Tables:   tableFor("app.example.com"),
		Backends: toAddress("127.0.0.1:1"),
	})
	defer front.Close()

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/", nil)
	req.Host = "unknown.example.org"
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatalf("Do() = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestProxyReturnsNotFoundBeforeTheFirstSnapshot(t *testing.T) {
	front := httptest.NewServer(&proxy.Handler{
		Tables:   &proxy.TableStore{},
		Backends: toAddress("127.0.0.1:1"),
	})
	defer front.Close()

	resp, err := front.Client().Get(front.URL + "/")
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestProxyReturnsBadGatewayWhenTheBackendCannotBeResolved(t *testing.T) {
	front := httptest.NewServer(&proxy.Handler{
		Tables: tableFor("app.example.com"),
		Backends: resolverFunc(func(context.Context, routing.Backend) (string, error) {
			return "", errors.New("no such Service")
		}),
	})
	defer front.Close()

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/", nil)
	req.Host = "app.example.com"
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatalf("Do() = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
}

func TestProxyReturnsBadGatewayWhenTheBackendIsUnreachable(t *testing.T) {
	front := httptest.NewServer(&proxy.Handler{
		Tables: tableFor("app.example.com"),
		// Port 1 on the loopback interface refuses connections.
		Backends: toAddress("127.0.0.1:1"),
	})
	defer front.Close()

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/", nil)
	req.Host = "app.example.com"
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatalf("Do() = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
}

func TestProxyPassesThroughAnUpgrade(t *testing.T) {
	// WebSocket is the reason this matters, but the mechanism under test is
	// the protocol upgrade itself: the 101, the Connection/Upgrade headers,
	// and the bytes that flow both ways afterwards.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "not an upgrade", http.StatusBadRequest)
			return
		}
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()
		io.WriteString(buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		buf.Flush()
		line, err := buf.ReadString('\n')
		if err != nil {
			return
		}
		io.WriteString(buf, "echo: "+line)
		buf.Flush()
	}))
	defer backend.Close()

	front := httptest.NewServer(&proxy.Handler{
		Tables:   tableFor("app.example.com"),
		Backends: toAddress(addressOf(t, backend)),
	})
	defer front.Close()

	conn, err := net.Dial("tcp", addressOf(t, front))
	if err != nil {
		t.Fatalf("Dial() = %v", err)
	}
	defer conn.Close()

	io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("ReadResponse() = %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusSwitchingProtocols)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		t.Errorf("Upgrade = %q, want %q", resp.Header.Get("Upgrade"), "websocket")
	}

	io.WriteString(conn, "ping\n")
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the echoed frame: %v", err)
	}
	if line != "echo: ping\n" {
		t.Errorf("read %q, want %q", line, "echo: ping\n")
	}
}

func TestProxyExposesTheMatchedRoute(t *testing.T) {
	// Authorisation runs in front of the proxy and needs to know which
	// Ingress owns the request (ADR 0002), so the match is carried on the
	// request context.
	var seen routing.Match
	var ok bool
	front := httptest.NewServer(&proxy.Handler{
		Tables:   tableFor("app.example.com"),
		Backends: toAddress("127.0.0.1:1"),
		Middleware: func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen, ok = proxy.MatchFromContext(r.Context())
				w.WriteHeader(http.StatusTeapot)
			})
		},
	})
	defer front.Close()

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/", nil)
	req.Host = "app.example.com"
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatalf("Do() = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("status = %d, want the middleware to have answered", resp.StatusCode)
	}
	if !ok {
		t.Fatal("MatchFromContext() = _, false, want the match")
	}
	want := routing.ResourceRef{Namespace: "apps", Name: "app"}
	if seen.Ingress != want {
		t.Errorf("match.Ingress = %+v, want %+v", seen.Ingress, want)
	}
}

// requestLine sends one request line to addr, with a Host header and nothing
// else, and returns the response. Going through a raw connection is the only
// way to put a path on the wire exactly as written: a client would be entitled
// to tidy it up on the way out, and what is under test here is what gated does
// with what it receives.
func requestLine(t *testing.T, addr, target, host string) *http.Response {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial() = %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	if _, err := io.WriteString(conn, "GET "+target+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("writing the request line: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ReadResponse() = %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestProxyRefusesAPathThatIsNotCanonical(t *testing.T) {
	// A path the backend would resolve somewhere else than gated matched
	// it must not reach the backend at all: authorisation compares paths as
	// strings, so it is the refusal that keeps the two readings from
	// diverging (ADR 0012).
	var reached bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		io.WriteString(w, "hello")
	}))
	defer backend.Close()

	front := httptest.NewServer(&proxy.Handler{
		Tables:   tableFor("app.example.com"),
		Backends: toAddress(addressOf(t, backend)),
	})
	defer front.Close()

	tests := []struct {
		name   string
		target string
		want   int
	}{
		{"a dot-dot segment", "/allowed/../secret", http.StatusBadRequest},
		{"a dot-dot segment, percent-encoded", "/allowed/%2e%2e/secret", http.StatusBadRequest},
		{"a dot-dot segment carrying a path parameter", "/allowed/..;/secret", http.StatusBadRequest},
		{"an encoded slash", "/allowed%2Fsecret", http.StatusBadRequest},
		{"a plain path", "/allowed/secret", http.StatusOK},
		{"an empty segment", "//allowed", http.StatusOK},
		{"a path parameter", "/allowed;jsessionid=x", http.StatusOK},
		{"a space, percent-encoded", "/allowed%20here", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reached = false
			resp := requestLine(t, addressOf(t, front), tc.target, "app.example.com")
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
			if want := tc.want == http.StatusOK; reached != want {
				t.Errorf("the backend was reached = %t, want %t", reached, want)
			}
		})
	}
}

func TestProxyRefusesBeforeItRoutes(t *testing.T) {
	// The refusal comes before the routing table is consulted, so a
	// non-canonical path is a 400 even where a 404 would otherwise be the
	// answer. Nothing downstream — the route, the authorisation decision —
	// ever sees the path.
	front := httptest.NewServer(&proxy.Handler{
		Tables:   tableFor("app.example.com"),
		Backends: toAddress("127.0.0.1:1"),
		Middleware: func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("the middleware ran, want the request refused before it")
			})
		},
	})
	defer front.Close()

	resp := requestLine(t, addressOf(t, front), "/a/../b", "nobody.example.org")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}
