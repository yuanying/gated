package controller

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gatedacme "github.com/yuanying/gated/internal/acme"
	"github.com/yuanying/gated/internal/authn"
)

// The two halves of a shared secret: one replica makes it, every replica reads
// it (ADR 0006).

// The intervals SecretEntry polls at. Rotation is rare and manual, so the
// steady-state interval is long; the short one is for the gap between a
// process starting and the Secret existing.
const (
	secretRefreshInterval = 5 * time.Minute
	secretRetryInterval   = 5 * time.Second
)

// SecretEntry keeps one entry of one Secret in memory.
//
// Reads go straight to the API server rather than through the informer cache,
// which holds TLS Secrets only (ADR 0013); an Opaque one read through it would
// come back as absent. Polling is how a rotation reaches a running process,
// since there is no informer to watch it.
//
// It runs on every replica. What it holds — the session signing key, an OAuth
// client secret — is needed to answer a request, so a replica that never wins
// the lease needs it just as much as the one that does (ADR 0006).
type SecretEntry struct {
	// Client reads the Secret. It must not be backed by the TLS-only cache.
	Client client.Client
	// Namespace, Name and Key locate the entry.
	Namespace string
	Name      string
	Key       string
	// What names the value in messages, for example "the session signing
	// key". It is what an operator reads when it cannot be found.
	What string
	// Log records the value arriving and changing.
	Log logr.Logger

	mu    sync.Mutex
	value []byte
}

// NeedLeaderElection reports that every replica reads for itself.
func (s *SecretEntry) NeedLeaderElection() bool { return false }

// Start keeps the held value up to date until the context is cancelled.
//
// It never fails the process. A Secret that is not there yet is ordinary — the
// leader may not have written it — and one that goes missing later must not
// take the data plane down with it, so the last good value is kept.
func (s *SecretEntry) Start(ctx context.Context) error {
	for {
		wait := secretRefreshInterval
		if _, err := s.refresh(ctx); err != nil {
			s.Log.V(1).Info("could not read "+s.What, "reason", err.Error())
			if !s.held() {
				wait = secretRetryInterval
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// Value returns the held entry, reading it once if nothing is held yet so that
// the first request does not have to wait for the poll.
func (s *SecretEntry) Value(ctx context.Context) ([]byte, error) {
	if held, ok := s.current(); ok {
		return held, nil
	}
	return s.refresh(ctx)
}

// Ready reports whether the value has been read, in the shape a health check
// wants. A replica that cannot verify a session cookie logs everybody out, so
// it is not ready to take traffic.
func (s *SecretEntry) Ready(*http.Request) error {
	if !s.held() {
		return fmt.Errorf("%s has not been read yet", s.What)
	}
	return nil
}

func (s *SecretEntry) refresh(ctx context.Context) ([]byte, error) {
	if s.Client == nil || s.Namespace == "" || s.Name == "" || s.Key == "" {
		return nil, fmt.Errorf("%s is not configured", s.What)
	}

	var secret corev1.Secret
	name := types.NamespacedName{Namespace: s.Namespace, Name: s.Name}
	if err := s.Client.Get(ctx, name, &secret); err != nil {
		return nil, fmt.Errorf("reading Secret %s: %w", name, err)
	}
	value := secret.Data[s.Key]
	if len(value) == 0 {
		return nil, fmt.Errorf("Secret %s has no %q entry", name, s.Key)
	}

	s.mu.Lock()
	changed := s.value != nil && string(s.value) != string(value)
	first := s.value == nil
	s.value = value
	s.mu.Unlock()

	switch {
	case first:
		s.Log.V(1).Info("read "+s.What, "namespace", s.Namespace, "secret", s.Name)
	case changed:
		s.Log.Info(s.What+" changed", "namespace", s.Namespace, "secret", s.Name)
	}
	return value, nil
}

func (s *SecretEntry) current() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.value, s.value != nil
}

func (s *SecretEntry) held() bool {
	_, ok := s.current()
	return ok
}

// SessionKeyGenerator writes the session signing key if nobody has.
//
// It is the leader's job. Every replica has to sign with the same key, so
// exactly one of them may decide what it is; the rest read what was written
// (ADR 0006). It runs once and returns — there is nothing to keep doing.
type SessionKeyGenerator struct {
	// Client creates the Secret. It must not be backed by the TLS-only
	// cache, or an existing Opaque Secret reads as absent and this would
	// try to create one that is already there.
	Client client.Client
	// Namespace and Name locate the Secret.
	Namespace string
	Name      string
	// Log records the one event worth seeing: a key being created.
	Log logr.Logger
}

// NeedLeaderElection reports that one replica decides what the key is.
func (g *SessionKeyGenerator) NeedLeaderElection() bool { return true }

// Start creates the Secret if it is absent, and otherwise leaves it alone.
//
// Nothing here ever overwrites an existing key. Replacing it is how every
// session in the installation is revoked at once (ADR 0003), which is a thing
// an operator does deliberately and never a thing a restart does.
func (g *SessionKeyGenerator) Start(ctx context.Context) error {
	if g.Client == nil || g.Namespace == "" || g.Name == "" {
		return errors.New("the session key Secret is not configured")
	}
	name := types.NamespacedName{Namespace: g.Namespace, Name: g.Name}

	var existing corev1.Secret
	err := g.Client.Get(ctx, name, &existing)
	switch {
	case err == nil:
		if len(existing.Data[authn.SessionKeySecretEntry]) < authn.MinKeySize {
			// Written by hand, or by an older version, and not usable.
			// Say so rather than replacing it: overwriting would log
			// out everybody who is signed in with whatever is there.
			g.Log.Error(nil, "the session key Secret holds no usable key; "+
				"put at least the minimum number of random bytes in it, or delete it and let gated write one",
				"namespace", g.Namespace, "secret", g.Name,
				"entry", authn.SessionKeySecretEntry, "minimumBytes", authn.MinKeySize)
		}
		return nil
	case !apierrors.IsNotFound(err):
		return fmt.Errorf("reading the session key Secret %s: %w", name, err)
	}

	key := make([]byte, authn.MinKeySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generating a session key: %w", err)
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: g.Namespace,
			Name:      g.Name,
			Labels:    map[string]string{gatedacme.ManagedByLabel: gatedacme.ManagedByValue},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{authn.SessionKeySecretEntry: key},
	}
	if err := g.Client.Create(ctx, secret); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Somebody got there first — two leaders during a
			// partition, or a hand-written Secret arriving between
			// the read and the write. Theirs is the key.
			return nil
		}
		return fmt.Errorf("creating the session key Secret %s: %w", name, err)
	}

	g.Log.Info("wrote a session signing key", "namespace", g.Namespace, "secret", g.Name)
	return nil
}
