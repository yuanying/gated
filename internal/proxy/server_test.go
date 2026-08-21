package proxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yuanying/gated/internal/proxy"
	"github.com/yuanying/gated/internal/routing"
)

// newEchoServer starts a backend that reports back what it was sent.
func newEchoServer(t *testing.T) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Forwarded-Proto", r.Header.Get("X-Forwarded-Proto"))
		w.Header().Set("X-Echo-Host", r.Host)
		io.WriteString(w, "ok")
	}))
	t.Cleanup(s.Close)
	return addressOf(t, s)
}

// newTLSServer starts an HTTPS listener on the loopback interface and returns
// its address.
func newTLSServer(t *testing.T, cfg *tls.Config, h http.Handler) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() = %v", err)
	}
	srv := &http.Server{Handler: h, TLSConfig: cfg}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// dialTo sends every connection to one address, so that a client can use a
// real hostname against a loopback listener.
func dialTo(addr string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
}

func TestServersServeBothListenersAndStopWithTheContext(t *testing.T) {
	cert := selfSigned(t, "app.example.com")
	certs := &proxy.Certificates{
		Tables: tlsTable(),
		Store: storeFunc(func(context.Context, routing.SecretRef) (*tls.Certificate, error) {
			return cert, nil
		}),
	}

	servers := &proxy.Servers{
		HTTPAddr:        "127.0.0.1:0",
		HTTPSAddr:       "127.0.0.1:0",
		Handler:         http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "secure") }),
		InsecureHandler: &proxy.InsecureHandler{},
		TLSConfig:       certs.TLSConfig(),
		ShutdownTimeout: 5 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- servers.Start(ctx) }()
	waitForAddresses(t, servers)

	// The plain listener redirects rather than proxying.
	plain := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, _ := http.NewRequest(http.MethodGet, "http://"+servers.HTTPAddress()+"/thing", nil)
	req.Host = "app.example.com"
	resp, err := plain.Do(req)
	if err != nil {
		t.Fatalf("Do() = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("status on the plain listener = %d, want %d", resp.StatusCode, http.StatusPermanentRedirect)
	}

	// The TLS listener terminates with the certificate the table names.
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	secure := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
		DialContext:     dialTo(servers.HTTPSAddress()),
	}}
	resp, err = secure.Get("https://app.example.com/")
	if err != nil {
		t.Fatalf("Get() over TLS = %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "secure" {
		t.Errorf("body = %q, want %q", body, "secure")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start() = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Start() did not return after the context was cancelled")
	}

	if _, err := plain.Get("http://" + servers.HTTPAddress() + "/"); err == nil {
		t.Error("the plain listener still answers after shutdown")
	}
}

func TestServersReportABindFailure(t *testing.T) {
	// A port that is already taken has to fail at startup, not silently
	// leave one listener unserved.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() = %v", err)
	}
	defer busy.Close()

	servers := &proxy.Servers{
		HTTPAddr:  busy.Addr().String(),
		HTTPSAddr: "127.0.0.1:0",
		Handler:   http.NotFoundHandler(),
	}
	if err := servers.Start(context.Background()); err == nil {
		t.Error("Start() = nil, want a bind failure")
	}
}

func TestServersDoNotNeedLeaderElection(t *testing.T) {
	// Every replica proxies; losing the lease must not take traffic with it
	// (ADR 0006).
	if (&proxy.Servers{}).NeedLeaderElection() {
		t.Error("NeedLeaderElection() = true, want false")
	}
}

func waitForAddresses(t *testing.T, s *proxy.Servers) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.HTTPAddress() != "" && s.HTTPSAddress() != "" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the servers never reported their listen addresses")
}
