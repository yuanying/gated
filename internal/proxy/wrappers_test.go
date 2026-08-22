package proxy_test

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yuanying/gated/internal/proxy"
)

// The access log wraps the whole handler chain, and the deadline wrapper sits
// inside it. http.ResponseController reaches the connection through Unwrap,
// so a wrapper in between that forgot Unwrap would make the deadlines
// silently stop applying (ADR 0030, ADR 0031). These two tests hold the pair
// together: the deadline still cuts a client through the access log, and an
// upgrade still passes through both.

func TestDeadlinesStillApplyThroughTheAccessLog(t *testing.T) {
	const size = 32 << 20
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, io.LimitReader(zeros{}, size))
	}))
	defer backend.Close()

	records := &proxy.AccessLog{}
	front := httptest.NewServer(records.Wrap(&proxy.Handler{
		Tables:               tableFor("app.example.com"),
		Backends:             toAddress(addressOf(t, backend)),
		ResponseWriteTimeout: testDeadline,
	}))
	defer front.Close()

	conn, err := net.Dial("tcp", addressOf(t, front))
	if err != nil {
		t.Fatalf("Dial() = %v", err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET /large HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
	time.Sleep(pastTheDeadline)

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, _ := io.Copy(io.Discard, conn)
	if n >= size {
		t.Errorf("read %d bytes through the access log, want the response cut off short of %d", n, size)
	}
}

func TestAnUpgradeStillPassesThroughBothWrappers(t *testing.T) {
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

	records := &proxy.AccessLog{}
	front := httptest.NewServer(records.Wrap(&proxy.Handler{
		Tables:               tableFor("app.example.com"),
		Backends:             toAddress(addressOf(t, backend)),
		BodyReadTimeout:      testDeadline,
		ResponseWriteTimeout: testDeadline,
	}))
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
	time.Sleep(pastTheDeadline)

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(conn, "ping\n")
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the echoed frame through both wrappers: %v", err)
	}
	if line != "echo: ping\n" {
		t.Errorf("read %q, want %q", line, "echo: ping\n")
	}
}
