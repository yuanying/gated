package proxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yuanying/gated/internal/proxy"
	"github.com/yuanying/gated/internal/routing"
)

// The deadlines under test are 60 and 90 seconds in production (ADR 0030).
// Nothing here waits that long: every test sets the field to a few tens of
// milliseconds and checks the behaviour, and the test beside them checks that
// a Handler left alone resolves to the real values.
const (
	testDeadline = 100 * time.Millisecond
	// pastTheDeadline is long enough that a deadline of testDeadline has
	// certainly expired, and short enough not to slow the suite down.
	pastTheDeadline = 400 * time.Millisecond
)

// bodyReport is what a backend saw of the request body.
type bodyReport struct {
	body string
	err  error
}

// echoBody starts a backend that reads the whole request body and reports what
// it managed to read.
func echoBody(t *testing.T) (addr string, reports <-chan bodyReport) {
	t.Helper()
	ch := make(chan bodyReport, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		ch <- bodyReport{body: string(b), err: err}
		if err != nil {
			// Answering 200 to a body that never arrived would
			// hide the cut behind a successful request.
			http.Error(w, "the body stopped", http.StatusBadRequest)
			return
		}
		io.WriteString(w, "read")
	}))
	t.Cleanup(s.Close)
	return addressOf(t, s), ch
}

// sendChunks writes each string to w with a pause between, then closes it.
func sendChunks(w *io.PipeWriter, pause time.Duration, chunks ...string) {
	for i, c := range chunks {
		if i > 0 {
			time.Sleep(pause)
		}
		if _, err := io.WriteString(w, c); err != nil {
			w.CloseWithError(err)
			return
		}
	}
	w.Close()
}

func TestProxyCutsAClientThatStopsSendingItsBody(t *testing.T) {
	backendAddr, reports := echoBody(t)
	front := httptest.NewServer(&proxy.Handler{
		Tables:          tableFor("app.example.com"),
		Backends:        toAddress(backendAddr),
		BodyReadTimeout: testDeadline,
	})
	defer front.Close()

	pr, pw := io.Pipe()
	go sendChunks(pw, pastTheDeadline, "first", "second")

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/", pr)
	req.Host = "app.example.com"
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatalf("Do() = %v", err)
	}
	defer resp.Body.Close()
	// 408 rather than the 502 an upstream failure gets, and rather than the
	// silence a client that hung up gets: the request never had a body to
	// forward, and saying so is the only way the client learns that.
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusRequestTimeout)
	}

	select {
	case got := <-reports:
		if strings.Contains(got.body, "second") {
			t.Errorf("the backend read %q, want the transfer cut before the pause ended", got.body)
		}
		if got.err == nil {
			t.Error("the backend read the body without error, want it cut off")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the backend never finished reading")
	}
}

func TestProxyLetsASlowButSteadyBodyThrough(t *testing.T) {
	// The deadline is on the gap between two reads, not on the transfer as
	// a whole (ADR 0030). This body takes longer than the deadline to
	// arrive and must still arrive in full: it is what a large upload looks
	// like scaled down.
	backendAddr, reports := echoBody(t)
	front := httptest.NewServer(&proxy.Handler{
		Tables:          tableFor("app.example.com"),
		Backends:        toAddress(backendAddr),
		BodyReadTimeout: testDeadline,
	})
	defer front.Close()

	chunks := []string{"a", "b", "c", "d", "e", "f"}
	pause := testDeadline / 4
	pr, pw := io.Pipe()
	go sendChunks(pw, pause, chunks...)

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/", pr)
	req.Host = "app.example.com"
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatalf("Do() = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	want := strings.Join(chunks, "")
	select {
	case got := <-reports:
		if got.err != nil {
			t.Errorf("the backend read the body with error %v, want it whole", got.err)
		}
		if got.body != want {
			t.Errorf("the backend read %q, want %q", got.body, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the backend never finished reading")
	}
	// The transfer as a whole outlasting the deadline is the point of the
	// test; if it did not, the test proves nothing.
	if total := time.Duration(len(chunks)-1) * pause; total <= testDeadline {
		t.Fatalf("the body took %v to send, which is under the deadline of %v", total, testDeadline)
	}
}

func TestProxyCutsAClientThatDoesNotReadTheResponse(t *testing.T) {
	// A client that asks for something large and then stops reading holds a
	// backend connection open through gated for as long as it likes. The
	// deadline on a single write is what ends that.
	const size = 32 << 20
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, io.LimitReader(zeros{}, size))
	}))
	defer backend.Close()

	front := httptest.NewServer(&proxy.Handler{
		Tables:               tableFor("app.example.com"),
		Backends:             toAddress(addressOf(t, backend)),
		ResponseWriteTimeout: testDeadline,
	})
	defer front.Close()

	conn, err := net.Dial("tcp", addressOf(t, front))
	if err != nil {
		t.Fatalf("Dial() = %v", err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET /large HTTP/1.1\r\nHost: app.example.com\r\n\r\n")

	// Nothing is read while the deadline passes, which is the whole
	// behaviour being provoked.
	time.Sleep(pastTheDeadline)

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, _ := io.Copy(io.Discard, conn)
	if n >= size {
		t.Errorf("read %d bytes, want the response cut off short of %d", n, size)
	}
}

// zeros is an endless source of one byte repeated.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestProxyLeavesAnUpgradedConnectionAlone(t *testing.T) {
	// Once a connection has been upgraded it is nobody's business here how
	// long it stays quiet: an idle WebSocket is ordinary (ADR 0030). The
	// deadlines are set far shorter than the silence this test sits
	// through.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		Tables:               tableFor("app.example.com"),
		Backends:             toAddress(addressOf(t, backend)),
		BodyReadTimeout:      testDeadline,
		ResponseWriteTimeout: testDeadline,
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

	// Silence, for several times the deadline that applied before the
	// upgrade.
	time.Sleep(pastTheDeadline)

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(conn, "ping\n")
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the echoed frame after the silence: %v", err)
	}
	if line != "echo: ping\n" {
		t.Errorf("read %q, want %q", line, "echo: ping\n")
	}
}

func TestProxyAppliesTheBodyDeadlineOverHTTP2(t *testing.T) {
	// http.ResponseController reaches the HTTP/2 server as well as the
	// HTTP/1 one, and the TLS listener advertises h2 (ADR 0013), so most
	// browser traffic arrives that way. The deadline has to hold there too.
	backendAddr, reports := echoBody(t)
	front := httptest.NewUnstartedServer(&proxy.Handler{
		Tables:          tableFor("app.example.com"),
		Backends:        toAddress(backendAddr),
		BodyReadTimeout: testDeadline,
	})
	front.EnableHTTP2 = true
	front.StartTLS()
	defer front.Close()

	pr, pw := io.Pipe()
	go sendChunks(pw, pastTheDeadline, "first", "second")

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/", pr)
	req.Host = "app.example.com"
	resp, err := front.Client().Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Fatalf("the request went out over HTTP/%d, want HTTP/2", resp.ProtoMajor)
		}
		if resp.StatusCode == http.StatusOK {
			t.Errorf("status = %d, want the transfer cut off", resp.StatusCode)
		}
	}

	select {
	case got := <-reports:
		if strings.Contains(got.body, "second") {
			t.Errorf("the backend read %q, want the transfer cut before the pause ended", got.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the backend never finished reading")
	}
}

func TestServersCloseAnIdleConnection(t *testing.T) {
	// A connection that has finished one request and starts no other is
	// gated's to reclaim; without a deadline it is held for as long as the
	// client cares to hold it (ADR 0030).
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
		IdleTimeout:     testDeadline,
		ShutdownTimeout: 5 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- servers.Start(ctx) }()
	waitForAddresses(t, servers)

	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	conn, err := tls.Dial("tcp", servers.HTTPSAddress(), &tls.Config{RootCAs: pool, ServerName: "app.example.com"})
	if err != nil {
		t.Fatalf("Dial() = %v", err)
	}
	defer conn.Close()

	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("ReadResponse() = %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// The connection is now idle and good for another request. It should
	// not be, for long.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := reader.ReadByte(); err == nil {
		t.Error("the idle connection sent a byte, want it closed")
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Error("the idle connection was still open after the deadline, want it closed")
	}

	cancel()
	<-done
}
