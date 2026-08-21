//go:build integration

package integration

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gatedacme "github.com/yuanying/gated/internal/acme"
	"github.com/yuanying/gated/internal/acme/http01"
	"github.com/yuanying/gated/internal/certs"
	"github.com/yuanying/gated/internal/proxy"
)

// memoryStore holds the outstanding challenges the way the Secret does.
//
// The Secret-backed store is exercised against a real API server in the
// envtest suite; what is under test here is the exchange with the CA, so the
// storage is stripped down to the interface the solver and the responder
// actually use.
type memoryStore struct {
	mu      sync.Mutex
	entries map[string]http01.Entry
}

func newMemoryStore() *memoryStore {
	return &memoryStore{entries: map[string]http01.Entry{}}
}

func (s *memoryStore) Put(_ context.Context, token string, e http01.Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[token] = e
	return nil
}

func (s *memoryStore) Delete(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, token)
	return nil
}

func (s *memoryStore) Challenges(context.Context) (map[string]http01.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]http01.Entry, len(s.entries))
	for k, v := range s.entries {
		out[k] = v
	}
	return out, nil
}

func (s *memoryStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// memoryAccounts keeps one account key for the life of the test. The
// Secret-backed store is covered by envtest.
type memoryAccounts struct {
	mu  sync.Mutex
	key crypto.Signer
}

func (a *memoryAccounts) AccountKey(context.Context) (crypto.Signer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.key == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		a.key = key
	}
	return a.key, nil
}

// counting wraps the challenge handler so a test can tell whether the CA
// really came to it, rather than inferring it from the order succeeding.
type counting struct {
	inner http.Handler
	hits  atomic.Int64
}

func (c *counting) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.hits.Add(1)
	c.inner.ServeHTTP(w, r)
}

// harness is one ACME client wired to a listener Pebble can reach.
type harness struct {
	client    *gatedacme.Client
	store     *memoryStore
	challenge *counting
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	directory, httpClient := pebble(t)

	store := newMemoryStore()
	responder := &http01.Responder{
		Source: store,
		// A single process here, so a snapshot is worth nothing: read
		// through on every request and let the exchange be about the
		// CA rather than about caching.
		TTL:     time.Nanosecond,
		MissTTL: time.Nanosecond,
	}
	challenge := &counting{inner: &proxy.InsecureHandler{Solver: responder}}
	listen(t, challenge)

	return &harness{
		client: &gatedacme.Client{
			DirectoryURL: directory,
			Email:        "gated@example.com",
			Accounts:     &memoryAccounts{},
			Solver: &http01.Solver{
				Store:        store,
				PollInterval: 10 * time.Millisecond,
				// One process, one snapshot, nothing to
				// propagate to.
				Propagation: 0,
			},
			HTTPClient: httpClient,
			UserAgent:  "gated-integration-test",
		},
		store:     store,
		challenge: challenge,
	}
}

// TestObtainsACertificate is the whole of stage three seen from outside: an
// order is placed, the challenge is answered by the listener gated serves on
// port 80, and a usable keypair comes back.
func TestObtainsACertificate(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	hosts := []string{"app.example.com", "api.example.com"}
	keypair, err := h.client.Obtain(ctx, hosts)
	if err != nil {
		t.Fatalf("Obtain() = %v", err)
	}

	// The proof that the certificate is usable is the renewal decision
	// itself: it parses the material, checks the key belongs to it and
	// checks every host is covered.
	decision := certs.Evaluate(&certs.Material{CertPEM: keypair.CertPEM, KeyPEM: keypair.KeyPEM}, hosts, time.Now())
	if decision.Renew {
		t.Errorf("the certificate just issued is already due for renewal: %s (%s)", decision.Reason, decision.Detail)
	}
	if decision.NotAfter.Before(time.Now().Add(24 * time.Hour)) {
		t.Errorf("NotAfter = %v, want a certificate with real validity", decision.NotAfter)
	}
	if got := strings.Count(string(keypair.CertPEM), "BEGIN CERTIFICATE"); got < 2 {
		t.Errorf("the PEM holds %d certificates, want the leaf and its chain", got)
	}

	// The CA validated through gated's own listener, not through anything
	// the test arranged behind its back.
	if h.challenge.hits.Load() < int64(len(hosts)) {
		t.Errorf("the challenge listener was asked %d times for %d hosts", h.challenge.hits.Load(), len(hosts))
	}
	// And nothing was left published afterwards.
	if h.store.len() != 0 {
		t.Errorf("%d challenges are still published after the order completed", h.store.len())
	}
}

// TestSecondOrderReusesTheAccount covers the renewal path: the same account
// key orders again, which is what happens every sixty days for the life of the
// installation.
func TestSecondOrderReusesTheAccount(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	first, err := h.client.Obtain(ctx, []string{"renew.example.com"})
	if err != nil {
		t.Fatalf("the first Obtain() = %v", err)
	}
	second, err := h.client.Obtain(ctx, []string{"renew.example.com"})
	if err != nil {
		t.Fatalf("the second Obtain() = %v", err)
	}
	if string(first.CertPEM) == string(second.CertPEM) {
		t.Error("the second order returned the first certificate; nothing was renewed")
	}
	if string(first.KeyPEM) == string(second.KeyPEM) {
		t.Error("the renewal reused the private key; each order gets its own")
	}
}

// TestRefusedOrderIsReported covers the failing path, so that a caller can
// tell an order that went wrong from one that quietly did nothing. Pebble
// refuses this name by configuration, the way a CA refuses a name it will not
// issue for.
func TestRefusedOrderIsReported(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	keypair, err := h.client.Obtain(ctx, []string{"blocked-domain.example"})
	if err == nil {
		t.Fatalf("Obtain() = %v, want the refusal", keypair)
	}
	if h.store.len() != 0 {
		t.Errorf("%d challenges are still published after the order failed", h.store.len())
	}
}

// TestOrderWithNoHostIsRejected keeps a mistake in the caller from becoming an
// exchange with the CA. No directory is involved: the client refuses before it
// opens a connection.
func TestOrderWithNoHostIsRejected(t *testing.T) {
	client := &gatedacme.Client{DirectoryURL: "https://example.invalid/dir"}
	if _, err := client.Obtain(context.Background(), nil); err == nil {
		t.Error("Obtain(nil) = nil, want an error")
	}
}
