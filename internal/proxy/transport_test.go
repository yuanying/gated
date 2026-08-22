package proxy

import (
	"net/http"
	"testing"
	"time"
)

// The values here are the ones ADR 0030 decided, and the reason each is not
// the standard library's default is in ADR 0013. Nothing observable from
// outside the process distinguishes them, so they are asserted directly.
func TestTheOutboundTransportIsGatedsOwn(t *testing.T) {
	tr := newTransport()

	// A proxy variable finding its way into the Pod would otherwise send
	// every backend call outside the cluster.
	if tr.Proxy != nil {
		t.Error("the transport reads a proxy from the environment, want it ignored")
	}
	if tr.MaxIdleConnsPerHost != 32 {
		t.Errorf("MaxIdleConnsPerHost = %d, want %d", tr.MaxIdleConnsPerHost, 32)
	}
	if tr.MaxIdleConns != 256 {
		t.Errorf("MaxIdleConns = %d, want %d", tr.MaxIdleConns, 256)
	}
	if tr.IdleConnTimeout != 90*time.Second {
		t.Errorf("IdleConnTimeout = %v, want %v", tr.IdleConnTimeout, 90*time.Second)
	}
	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("TLSHandshakeTimeout = %v, want %v", tr.TLSHandshakeTimeout, 10*time.Second)
	}
	// A response that takes minutes to begin is ordinary here, so there is
	// no deadline on the backend's first byte (ADR 0030).
	if tr.ResponseHeaderTimeout != 0 {
		t.Errorf("ResponseHeaderTimeout = %v, want no limit", tr.ResponseHeaderTimeout)
	}
	// Backends are spoken to in the clear, where HTTP/2 does not apply.
	if tr.ForceAttemptHTTP2 {
		t.Error("the transport attempts HTTP/2, want HTTP/1.1 to a plain backend")
	}
	if backendDialer.Timeout != 10*time.Second {
		t.Errorf("the dial deadline = %v, want %v", backendDialer.Timeout, 10*time.Second)
	}
}

func TestAHandlerWithoutATransportUsesGatedsOwn(t *testing.T) {
	handler := &Handler{}
	handler.init()
	if _, ok := handler.proxy.Transport.(*http.Transport); !ok {
		t.Fatalf("the reverse proxy's transport is %T, want gated's own *http.Transport", handler.proxy.Transport)
	}
	if handler.proxy.BufferPool == nil {
		t.Fatal("the reverse proxy has no buffer pool, want one")
	}
	b := handler.proxy.BufferPool.Get()
	if len(b) != 32<<10 {
		t.Errorf("a pooled buffer is %d bytes, want %d", len(b), 32<<10)
	}
	handler.proxy.BufferPool.Put(b)
}

func TestAHandlerKeepsTheTransportItWasGiven(t *testing.T) {
	given := &http.Transport{}
	handler := &Handler{Transport: given}
	handler.init()
	if handler.proxy.Transport != given {
		t.Error("the reverse proxy replaced the transport it was given")
	}
}
