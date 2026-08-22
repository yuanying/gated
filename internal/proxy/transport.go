package proxy

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// backendDialer opens the connections to backends.
//
// It is a package-level value so that the deadline it carries can be read
// back; an http.Transport keeps only the function, not what it was built from.
var backendDialer = &net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 30 * time.Second,
}

// newTransport builds the transport gated forwards over (ADR 0013, ADR 0030).
//
// It is not http.DefaultTransport for two reasons. That one reads a proxy out
// of the environment, and a proxy variable finding its way into the Pod would
// send every backend call outside the cluster. And it keeps two idle
// connections per backend, so a third concurrent request builds a new one and
// leaves the backend a socket in TIME_WAIT for it.
//
// There is deliberately no deadline on the backend's response headers: a
// response that takes minutes to begin is ordinary traffic here.
func newTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           backendDialer.DialContext,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		// Backends are spoken to in the clear (ADR 0013), where this
		// does nothing but leave the impression that h2c is expected.
		ForceAttemptHTTP2: false,
	}
}

// copyBufferSize is the size of one buffer the reverse proxy copies a body
// through. It is the size the standard library uses when given no pool.
const copyBufferSize = 32 << 10

// bufferPool hands the reverse proxy a copy buffer per transfer rather than
// letting it allocate one. It satisfies httputil.BufferPool.
type bufferPool struct {
	pool sync.Pool
}

func newBufferPool() *bufferPool {
	return &bufferPool{pool: sync.Pool{
		New: func() any {
			b := make([]byte, copyBufferSize)
			return &b
		},
	}}
}

func (p *bufferPool) Get() []byte {
	b, ok := p.pool.Get().(*[]byte)
	if !ok {
		return make([]byte, copyBufferSize)
	}
	return *b
}

func (p *bufferPool) Put(b []byte) {
	p.pool.Put(&b)
}
