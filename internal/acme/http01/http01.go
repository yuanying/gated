// Package http01 answers the ACME HTTP-01 challenge out of a Secret every
// replica can read.
//
// The order is placed by one replica, but the CA reaches whichever replica the
// load balancer hands it. A challenge held in the ordering process's memory is
// therefore answered only some of the time, and a validation that lands
// elsewhere fails. So the token goes into a Secret, and answering it is the
// job of every replica rather than of the one that asked for the certificate
// (ADR 0006).
//
// The write side is Solver, which the ACME client drives. The read side is
// Responder, which the plain HTTP listener consults.
package http01

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"

	"github.com/yuanying/gated/internal/acme"
)

// Entry is one outstanding challenge as it is shared between replicas.
//
// The host is carried for the sake of anybody reading the Secret or the logs.
// Answering does not depend on it: the token is what the CA asks for, it is
// unguessable, and it is published only while the order that produced it is in
// flight.
type Entry struct {
	Host             string `json:"host"`
	KeyAuthorization string `json:"keyAuthorization"`
}

// Source reads the outstanding challenges.
type Source interface {
	Challenges(ctx context.Context) (map[string]Entry, error)
}

// Store reads and writes them.
type Store interface {
	Source
	Put(ctx context.Context, token string, entry Entry) error
	Delete(ctx context.Context, token string) error
}

// Defaults for the timings that matter.
const (
	// DefaultTTL is how long a replica reuses a snapshot of the
	// outstanding challenges.
	DefaultTTL = 30 * time.Second
	// DefaultMissTTL bounds how often a request for a token the snapshot
	// does not have costs a fresh read. It is what keeps a flood of
	// requests for challenge paths from becoming a flood of API calls,
	// while still letting a token that arrived a moment ago be found.
	DefaultMissTTL = time.Second
	// DefaultPropagation is how long Present waits after the write is
	// readable. It is measured against MissTTL rather than TTL: a replica
	// asked for a token its snapshot does not have takes a fresh look, so
	// what has to elapse is only long enough for that snapshot to be older
	// than MissTTL.
	DefaultPropagation = 2 * DefaultMissTTL
	// DefaultPollInterval and DefaultTimeout bound the wait for the write
	// to become readable at all.
	DefaultPollInterval = 200 * time.Millisecond
	DefaultTimeout      = 30 * time.Second
)

// Solver publishes challenges into the shared store.
type Solver struct {
	// Store holds the outstanding challenges. Required.
	Store Store
	// Propagation is how long Present waits, after confirming the write is
	// readable, before reporting the challenge ready.
	//
	// Zero means no wait, which is only right when there is exactly one
	// replica. With more than one it has to exceed the Responder's
	// MissTTL, or a replica whose snapshot is too fresh to be refreshed
	// answers a 404 to the validation request.
	Propagation time.Duration
	// PollInterval and Timeout bound the wait for the write to be readable.
	PollInterval time.Duration
	Timeout      time.Duration
	// Log records what was published. The zero Logger discards.
	Log logr.Logger
}

// Type reports the challenge this solver answers.
func (s *Solver) Type() string { return acme.ChallengeHTTP01 }

// Present publishes a challenge and does not return until it can be read back.
//
// Reading it back is not a formality. The ACME client accepts the challenge
// the instant this returns, and the CA may arrive immediately after; a write
// that has not landed by then costs the whole order.
func (s *Solver) Present(ctx context.Context, ch acme.Challenge) error {
	if s.Store == nil {
		return fmt.Errorf("the HTTP-01 solver has no store")
	}
	entry := Entry{Host: ch.Identifier, KeyAuthorization: ch.Response}
	if err := s.Store.Put(ctx, ch.Token, entry); err != nil {
		return fmt.Errorf("publishing the challenge for %s: %w", ch.Identifier, err)
	}
	if err := s.waitReadable(ctx, ch.Token); err != nil {
		return err
	}
	if s.Propagation > 0 {
		select {
		case <-time.After(s.Propagation):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.Log.V(1).Info("published an HTTP-01 challenge", "host", ch.Identifier)
	return nil
}

// CleanUp withdraws a challenge, tolerating one that is already gone.
func (s *Solver) CleanUp(ctx context.Context, ch acme.Challenge) error {
	if s.Store == nil {
		return nil
	}
	if err := s.Store.Delete(ctx, ch.Token); err != nil {
		return fmt.Errorf("withdrawing the challenge for %s: %w", ch.Identifier, err)
	}
	s.Log.V(1).Info("withdrew an HTTP-01 challenge", "host", ch.Identifier)
	return nil
}

// waitReadable polls until the token comes back out of the store.
func (s *Solver) waitReadable(ctx context.Context, token string) error {
	interval := s.PollInterval
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var lastErr error
	for {
		entries, err := s.Store.Challenges(deadline)
		if err != nil {
			lastErr = err
		} else if _, ok := entries[token]; ok {
			return nil
		} else {
			lastErr = fmt.Errorf("the challenge is not readable yet")
		}

		select {
		case <-time.After(interval):
		case <-deadline.Done():
			return fmt.Errorf("waiting for the challenge to become readable: %w", lastErr)
		}
	}
}

// Responder answers challenge requests on the plain listener.
//
// It reads the shared store rather than any memory of its own, so a replica
// that never placed an order still answers. Requests for challenge paths come
// from the open internet, so the snapshot is reused for a while rather than
// read afresh each time: without that, anybody could turn a request loop into
// API server load.
type Responder struct {
	// Source reads the outstanding challenges. Required.
	Source Source
	// TTL is how long a snapshot is reused for a token it contains.
	TTL time.Duration
	// MissTTL is how long a snapshot is reused for a token it does not
	// contain. It is shorter, so that a token published a moment ago is
	// found without waiting out the full TTL.
	MissTTL time.Duration
	// Now reads the clock, overridable in tests.
	Now func() time.Time
	// Log records lookups that failed. The zero Logger discards.
	Log logr.Logger

	mu        sync.Mutex
	entries   map[string]Entry
	fetched   time.Time
	haveFetch bool
}

// KeyAuthorization returns what to serve for a token, or reports that this is
// not a challenge gated is waiting on.
func (r *Responder) KeyAuthorization(ctx context.Context, host, token string) (string, bool) {
	if r.Source == nil || token == "" {
		return "", false
	}

	entries := r.snapshot(ctx, false)
	if entry, ok := entries[token]; ok {
		return entry.KeyAuthorization, true
	}
	// A miss may simply be a snapshot older than the write. One more look,
	// rate limited by MissTTL.
	entries = r.snapshot(ctx, true)
	if entry, ok := entries[token]; ok {
		return entry.KeyAuthorization, true
	}
	r.Log.V(1).Info("no such ACME challenge", "host", host)
	return "", false
}

// snapshot returns the outstanding challenges, refreshing when the cached copy
// is older than the applicable lifetime.
//
// A refresh that fails leaves the previous snapshot in place. The API server
// being briefly away must not turn a challenge gated already knows about into
// a 404.
func (r *Responder) snapshot(ctx context.Context, afterMiss bool) map[string]Entry {
	r.mu.Lock()
	defer r.mu.Unlock()

	ttl := r.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if afterMiss {
		ttl = r.MissTTL
		if ttl <= 0 {
			ttl = DefaultMissTTL
		}
	}

	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	if r.haveFetch && now().Sub(r.fetched) < ttl {
		return r.entries
	}

	entries, err := r.Source.Challenges(ctx)
	if err != nil {
		r.Log.V(1).Info("reading the outstanding ACME challenges failed", "error", err.Error())
		return r.entries
	}
	r.entries = entries
	r.fetched = now()
	r.haveFetch = true
	return entries
}
