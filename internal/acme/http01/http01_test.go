package http01_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/yuanying/gated/internal/acme"
	"github.com/yuanying/gated/internal/acme/http01"
	"github.com/yuanying/gated/internal/proxy"
)

// memStore stands in for the Secret. It counts reads so that the caching the
// responder does can be asserted on, and can be made to fail or to lag.
type memStore struct {
	mu sync.Mutex

	entries map[string]http01.Entry
	reads   int
	// visibleAfter delays what a read sees, standing in for a write that
	// has not reached every replica yet.
	visibleAfter int
	pending      map[string]http01.Entry
	// readErr, when set, fails every read.
	readErr error
	// writeErr, when set, fails every write.
	writeErr error
}

func newMemStore() *memStore {
	return &memStore{entries: map[string]http01.Entry{}, pending: map[string]http01.Entry{}}
}

func (s *memStore) Put(_ context.Context, token string, e http01.Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeErr != nil {
		return s.writeErr
	}
	if s.visibleAfter > 0 {
		s.pending[token] = e
		return nil
	}
	s.entries[token] = e
	return nil
}

func (s *memStore) Delete(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeErr != nil {
		return s.writeErr
	}
	delete(s.entries, token)
	delete(s.pending, token)
	return nil
}

func (s *memStore) Challenges(context.Context) (map[string]http01.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if s.readErr != nil {
		return nil, s.readErr
	}
	if s.visibleAfter > 0 {
		s.visibleAfter--
		if s.visibleAfter == 0 {
			for token, e := range s.pending {
				s.entries[token] = e
			}
			s.pending = map[string]http01.Entry{}
		}
	}
	out := make(map[string]http01.Entry, len(s.entries))
	for token, e := range s.entries {
		out[token] = e
	}
	return out, nil
}

func (s *memStore) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

// clock is a hand-wound clock so the responder's caching is testable without
// sleeping.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// TestRespondsAfterPresent is the whole point of the package: what the solver
// writes, a replica that never saw the order can answer.
func TestRespondsAfterPresent(t *testing.T) {
	store := newMemStore()
	solver := &http01.Solver{Store: store, Propagation: 0}
	responder := &http01.Responder{Source: store, TTL: 5 * time.Second}

	ch := acme.Challenge{Type: acme.ChallengeHTTP01, Identifier: "app.example.com", Token: "tok", Response: "tok.keyauth"}
	if err := solver.Present(context.Background(), ch); err != nil {
		t.Fatalf("Present() = %v", err)
	}

	got, ok := responder.KeyAuthorization(context.Background(), "app.example.com", "tok")
	if !ok || got != "tok.keyauth" {
		t.Errorf("KeyAuthorization() = %q, %v; want %q, true", got, ok, "tok.keyauth")
	}
}

func TestSolverType(t *testing.T) {
	solver := &http01.Solver{Store: newMemStore()}

	if got := solver.Type(); got != acme.ChallengeHTTP01 {
		t.Errorf("Type() = %q, want %q", got, acme.ChallengeHTTP01)
	}
	var _ acme.Solver = solver
	var _ proxy.ChallengeSolver = &http01.Responder{}
}

// TestPresentWaitsForVisibility covers the reason Present exists at all: it
// must not return until a replica reading the shared state can see the token,
// or the CA validates against a replica that answers a 404 (ADR 0006).
func TestPresentWaitsForVisibility(t *testing.T) {
	store := newMemStore()
	store.visibleAfter = 3
	solver := &http01.Solver{Store: store, PollInterval: time.Millisecond, Timeout: 5 * time.Second, Propagation: 0}

	ch := acme.Challenge{Type: acme.ChallengeHTTP01, Identifier: "app.example.com", Token: "tok", Response: "tok.keyauth"}
	if err := solver.Present(context.Background(), ch); err != nil {
		t.Fatalf("Present() = %v", err)
	}
	if store.readCount() < 3 {
		t.Errorf("Present returned after %d reads; it did not wait for the write to be visible", store.readCount())
	}
}

func TestPresentGivesUp(t *testing.T) {
	store := newMemStore()
	store.visibleAfter = 1000
	solver := &http01.Solver{Store: store, PollInterval: time.Millisecond, Timeout: 20 * time.Millisecond, Propagation: 0}

	err := solver.Present(context.Background(), acme.Challenge{Token: "tok", Response: "tok.keyauth"})
	if err == nil {
		t.Fatal("Present() = nil, want an error once the token never becomes visible")
	}
}

func TestPresentReportsAWriteFailure(t *testing.T) {
	store := newMemStore()
	store.writeErr = errors.New("no")
	solver := &http01.Solver{Store: store, Propagation: 0}

	if err := solver.Present(context.Background(), acme.Challenge{Token: "tok", Response: "r"}); err == nil {
		t.Fatal("Present() = nil, want the write failure")
	}
}

func TestCleanUpStopsTheAnswer(t *testing.T) {
	store := newMemStore()
	tick := &clock{now: time.Unix(0, 0)}
	solver := &http01.Solver{Store: store, Propagation: 0}
	responder := &http01.Responder{Source: store, TTL: 5 * time.Second, Now: tick.Now}

	ch := acme.Challenge{Token: "tok", Identifier: "app.example.com", Response: "tok.keyauth"}
	if err := solver.Present(context.Background(), ch); err != nil {
		t.Fatalf("Present() = %v", err)
	}
	if _, ok := responder.KeyAuthorization(context.Background(), "app.example.com", "tok"); !ok {
		t.Fatal("the challenge is not answered before cleanup")
	}
	if err := solver.CleanUp(context.Background(), ch); err != nil {
		t.Fatalf("CleanUp() = %v", err)
	}

	tick.advance(6 * time.Second)
	if _, ok := responder.KeyAuthorization(context.Background(), "app.example.com", "tok"); ok {
		t.Error("the challenge is still answered after cleanup")
	}
}

// TestCleanUpTolerates covers being called for a challenge that is already
// gone, which happens whenever an order fails after some authorizations have
// already been torn down.
func TestCleanUpTolerates(t *testing.T) {
	store := newMemStore()
	solver := &http01.Solver{Store: store, Propagation: 0}
	if err := solver.CleanUp(context.Background(), acme.Challenge{Token: "never-presented"}); err != nil {
		t.Errorf("CleanUp() = %v, want nil for a challenge that is not there", err)
	}
}

// TestPresentWaitsForPropagation covers the deliberate pause after the write
// is readable. A replica serving from a snapshot it took a moment ago cannot
// see the new token yet, and the CA reaches whichever replica it likes.
func TestPresentWaitsForPropagation(t *testing.T) {
	store := newMemStore()
	solver := &http01.Solver{Store: store, Propagation: 80 * time.Millisecond}

	started := time.Now()
	if err := solver.Present(context.Background(), acme.Challenge{Token: "tok", Response: "tok.keyauth"}); err != nil {
		t.Fatalf("Present() = %v", err)
	}
	if waited := time.Since(started); waited < 80*time.Millisecond {
		t.Errorf("Present returned after %v, want it to wait out the propagation delay", waited)
	}
}

// TestResponderCaches bounds what a flood of requests for challenge paths
// costs the API server.
func TestResponderCaches(t *testing.T) {
	store := newMemStore()
	tick := &clock{now: time.Unix(0, 0)}
	responder := &http01.Responder{Source: store, TTL: 5 * time.Second, Now: tick.Now}
	store.entries["tok"] = http01.Entry{Host: "app.example.com", KeyAuthorization: "tok.keyauth"}

	for range 50 {
		responder.KeyAuthorization(context.Background(), "app.example.com", "tok")
		responder.KeyAuthorization(context.Background(), "app.example.com", "missing")
	}
	if got := store.readCount(); got != 1 {
		t.Errorf("%d reads for a hundred lookups, want 1 within the TTL", got)
	}

	tick.advance(6 * time.Second)
	responder.KeyAuthorization(context.Background(), "app.example.com", "tok")
	if got := store.readCount(); got != 2 {
		t.Errorf("%d reads after the TTL elapsed, want 2", got)
	}
}

// TestResponderKeepsTheLastSnapshot covers the API server being unreachable
// mid-validation: the challenge gated already knows about still gets answered.
func TestResponderKeepsTheLastSnapshot(t *testing.T) {
	store := newMemStore()
	tick := &clock{now: time.Unix(0, 0)}
	responder := &http01.Responder{Source: store, TTL: 5 * time.Second, Now: tick.Now}
	store.entries["tok"] = http01.Entry{Host: "app.example.com", KeyAuthorization: "tok.keyauth"}

	if _, ok := responder.KeyAuthorization(context.Background(), "app.example.com", "tok"); !ok {
		t.Fatal("the challenge is not answered while the store works")
	}

	store.mu.Lock()
	store.readErr = errors.New("the API server is away")
	store.mu.Unlock()
	tick.advance(time.Minute)

	if got, ok := responder.KeyAuthorization(context.Background(), "app.example.com", "tok"); !ok || got != "tok.keyauth" {
		t.Errorf("KeyAuthorization() = %q, %v; want the last known answer", got, ok)
	}
}

func TestResponderWithoutASource(t *testing.T) {
	responder := &http01.Responder{}
	if _, ok := responder.KeyAuthorization(context.Background(), "app.example.com", "tok"); ok {
		t.Error("a responder with no source answered a challenge")
	}
}
