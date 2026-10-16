package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gatedacme "github.com/yuanying/gated/internal/acme"
	"github.com/yuanying/gated/internal/assertion"
)

// The keys the assertion handed to a backend is signed with (ADR 0034). They
// are kept the way the session key is (ADR 0006): one replica makes them,
// every replica reads them, and only an operator ever changes them.

// AssertionKeys keeps the key set of one Secret in memory.
//
// It reads the whole Secret rather than one entry, because the set is the
// signing key and whatever is published beside it, and a rotation changes both
// at once. Like SecretEntry it reads past the TLS-only cache and polls, and it
// keeps the last set that could be read when a later read fails: a Secret
// mangled halfway through a rotation must not stop a running replica from
// vouching for anybody.
type AssertionKeys struct {
	// Client reads the Secret. It must not be backed by the TLS-only cache.
	Client client.Client
	// Namespace and Name locate the Secret.
	Namespace string
	Name      string
	// Log records the keys arriving and changing.
	Log logr.Logger

	mu   sync.Mutex
	set  *assertion.KeySet
	data map[string][]byte
}

// NeedLeaderElection reports that every replica reads for itself.
func (k *AssertionKeys) NeedLeaderElection() bool { return false }

// Start keeps the held keys up to date until the context is cancelled. It never
// fails the process, for the reasons SecretEntry.Start gives.
func (k *AssertionKeys) Start(ctx context.Context) error {
	keepReading(ctx, func(ctx context.Context) error {
		_, err := k.refresh(ctx)
		return err
	}, k.held, func(err error) {
		// Unlike a key that is not there yet, one that cannot be read
		// is somebody's mistake, and it stays one until they look.
		k.Log.Info("could not read the assertion signing keys", "reason", err.Error())
	})
	return nil
}

// KeySet returns the held keys, reading them once if nothing is held yet so
// that the first request does not have to wait for the poll.
func (k *AssertionKeys) KeySet(ctx context.Context) (*assertion.KeySet, error) {
	if set := k.current(); set != nil {
		return set, nil
	}
	return k.refresh(ctx)
}

// Ready reports whether the keys have been read, in the shape a health check
// wants. A replica that cannot sign forwards every logged-in request as though
// nobody were logged in, so it is not ready to take traffic.
func (k *AssertionKeys) Ready(*http.Request) error {
	if !k.held() {
		return errors.New("the assertion signing keys have not been read yet")
	}
	return nil
}

func (k *AssertionKeys) refresh(ctx context.Context) (*assertion.KeySet, error) {
	if k.Client == nil || k.Namespace == "" || k.Name == "" {
		return nil, errors.New("the assertion signing keys are not configured")
	}

	var secret corev1.Secret
	name := types.NamespacedName{Namespace: k.Namespace, Name: k.Name}
	if err := k.Client.Get(ctx, name, &secret); err != nil {
		return nil, fmt.Errorf("reading Secret %s: %w", name, err)
	}
	set, err := assertion.ParseKeySet(secret.Data)
	if err != nil {
		return nil, fmt.Errorf("Secret %s: %w", name, err)
	}

	k.mu.Lock()
	first := k.set == nil
	changed := !first && !sameKeyData(k.data, secret.Data)
	k.set, k.data = set, secret.Data
	k.mu.Unlock()

	switch {
	case first:
		k.Log.V(1).Info("read the assertion signing keys", "namespace", k.Namespace, "secret", k.Name)
	case changed:
		k.Log.Info("the assertion signing keys changed", "namespace", k.Namespace, "secret", k.Name)
	}
	return set, nil
}

func (k *AssertionKeys) current() *assertion.KeySet {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.set
}

func (k *AssertionKeys) held() bool { return k.current() != nil }

// sameKeyData reports whether two readings of the Secret hold the same keys.
func sameKeyData(a, b map[string][]byte) bool {
	for _, entry := range []string{assertion.SigningKeyEntry, assertion.PublishedKeysEntry} {
		if !bytes.Equal(a[entry], b[entry]) {
			return false
		}
	}
	return true
}

// AssertionKeyGenerator writes a signing key if nobody has.
//
// It is the leader's job, for the same reason as the session key: every
// replica has to sign with the same key, so exactly one of them may decide what
// it is (ADR 0006). It runs once and returns.
type AssertionKeyGenerator struct {
	// Client creates the Secret. It must not be backed by the TLS-only
	// cache, or an existing Opaque Secret reads as absent.
	Client client.Client
	// Namespace and Name locate the Secret.
	Namespace string
	Name      string
	// Log records a key being created, and a Secret that holds none.
	Log logr.Logger
}

// NeedLeaderElection reports that one replica decides what the key is.
func (g *AssertionKeyGenerator) NeedLeaderElection() bool { return true }

// Start creates the Secret if it is absent, and otherwise leaves it alone.
//
// Nothing here ever overwrites an existing Secret. Changing the keys is a
// rotation, which is an operator's deliberate act done in steps (ADR 0034);
// a restart that replaced them would have backends refusing every assertion
// until they fetched the keys again.
func (g *AssertionKeyGenerator) Start(ctx context.Context) error {
	if g.Client == nil || g.Namespace == "" || g.Name == "" {
		return errors.New("the assertion key Secret is not configured")
	}
	name := types.NamespacedName{Namespace: g.Namespace, Name: g.Name}

	var existing corev1.Secret
	err := g.Client.Get(ctx, name, &existing)
	switch {
	case err == nil:
		if _, err := assertion.ParseKeySet(existing.Data); err != nil {
			// Written by hand and not usable. Say so rather than
			// replacing it: whatever is there may be half of a
			// rotation somebody is in the middle of.
			g.Log.Error(err, "the assertion key Secret holds no usable keys; "+
				"fix it, or delete it and let gated write a new one",
				"namespace", g.Namespace, "secret", g.Name)
		}
		return nil
	case !apierrors.IsNotFound(err):
		return fmt.Errorf("reading the assertion key Secret %s: %w", name, err)
	}

	data, err := assertion.GenerateSecretData()
	if err != nil {
		return err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: g.Namespace,
			Name:      g.Name,
			Labels:    map[string]string{gatedacme.ManagedByLabel: gatedacme.ManagedByValue},
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
	if err := g.Client.Create(ctx, secret); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Somebody got there first. Theirs is the key.
			return nil
		}
		return fmt.Errorf("creating the assertion key Secret %s: %w", name, err)
	}

	g.Log.Info("wrote an assertion signing key", "namespace", g.Namespace, "secret", g.Name)
	return nil
}
