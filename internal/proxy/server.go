package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

// defaultShutdownTimeout bounds how long a graceful shutdown waits for
// in-flight requests before connections are closed underneath them.
const defaultShutdownTimeout = 30 * time.Second

// defaultReadHeaderTimeout bounds how long a connection may sit having sent
// nothing, so that idle connections cannot be used to exhaust the listener.
const defaultReadHeaderTimeout = 20 * time.Second

// Servers runs the two listeners as one unit.
//
// It satisfies controller-runtime's Runnable and does not need leader
// election: every replica serves traffic, and losing the lease must not take
// the data plane with it (ADR 0006).
type Servers struct {
	// HTTPAddr is the plain listener. It answers ACME challenges and
	// redirects everything else.
	HTTPAddr string
	// HTTPSAddr is the TLS listener.
	HTTPSAddr string

	// Handler serves TLS-terminated traffic.
	Handler http.Handler
	// InsecureHandler serves the plain listener. A nil handler redirects
	// everything and answers no challenges.
	InsecureHandler http.Handler
	// TLSConfig terminates TLS. Required.
	TLSConfig *tls.Config

	// ShutdownTimeout bounds the graceful shutdown of both listeners.
	ShutdownTimeout time.Duration
	// ReadHeaderTimeout bounds how long a client may take to send its
	// request headers.
	ReadHeaderTimeout time.Duration
	// Log reports the lifecycle of the listeners. The zero Logger discards.
	Log logr.Logger

	mu        sync.Mutex
	httpAddr  string
	httpsAddr string
}

// NeedLeaderElection reports that the data plane runs on every replica.
func (s *Servers) NeedLeaderElection() bool { return false }

// HTTPAddress is the address the plain listener actually bound to, which
// differs from HTTPAddr when the port was left to the kernel. It is empty
// until Start has bound.
func (s *Servers) HTTPAddress() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.httpAddr
}

// HTTPSAddress is the address the TLS listener actually bound to.
func (s *Servers) HTTPSAddress() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.httpsAddr
}

// Start binds and serves both listeners, and returns once both have shut down.
//
// Both are bound before either is served, so that a port already in use is a
// startup failure rather than a process that quietly serves half its traffic.
func (s *Servers) Start(ctx context.Context) error {
	if s.TLSConfig == nil {
		return errors.New("the HTTPS listener has no TLS configuration")
	}

	httpLn, err := net.Listen("tcp", s.HTTPAddr)
	if err != nil {
		return fmt.Errorf("binding the HTTP listener on %s: %w", s.HTTPAddr, err)
	}
	httpsLn, err := net.Listen("tcp", s.HTTPSAddr)
	if err != nil {
		httpLn.Close()
		return fmt.Errorf("binding the HTTPS listener on %s: %w", s.HTTPSAddr, err)
	}

	s.mu.Lock()
	s.httpAddr = httpLn.Addr().String()
	s.httpsAddr = httpsLn.Addr().String()
	s.mu.Unlock()

	insecure := s.InsecureHandler
	if insecure == nil {
		insecure = &InsecureHandler{Log: s.Log}
	}
	plain := s.newServer(insecure)
	secure := s.newServer(s.Handler)
	secure.TLSConfig = s.TLSConfig

	s.Log.Info("serving", "http", s.httpAddr, "https", s.httpsAddr)

	errs := make(chan error, 2)
	go func() { errs <- ignoreClosed(plain.Serve(httpLn)) }()
	// ServeTLS with no files uses the TLSConfig, and configures HTTP/2 for
	// the ALPN protocols the config advertises.
	go func() { errs <- ignoreClosed(secure.ServeTLS(httpsLn, "", "")) }()

	select {
	case err := <-errs:
		// One listener died on its own. Take the other down with it rather
		// than serving half the traffic.
		plain.Close()
		secure.Close()
		<-errs
		return err
	case <-ctx.Done():
	}

	timeout := s.ShutdownTimeout
	if timeout <= 0 {
		timeout = defaultShutdownTimeout
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()

	s.Log.Info("draining")
	shutdownErr := errors.Join(plain.Shutdown(shutdownCtx), secure.Shutdown(shutdownCtx))
	// Shutdown makes both Serve calls return; collect them so the goroutines
	// are done before Start is.
	<-errs
	<-errs
	s.Log.Info("stopped")
	return shutdownErr
}

func (s *Servers) newServer(h http.Handler) *http.Server {
	timeout := s.ReadHeaderTimeout
	if timeout <= 0 {
		timeout = defaultReadHeaderTimeout
	}
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: timeout,
		ErrorLog:          nil,
	}
}

// ignoreClosed treats the sentinel a shut-down server returns as success.
func ignoreClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
