//go:build envtest

package envtest_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/yuanying/gated/internal/assertion"
	"github.com/yuanying/gated/internal/assertion/assertiontest"
	"github.com/yuanying/gated/internal/controller"
)

// The keys a backend's assertion is signed with are shared the way the session
// key is (ADR 0034, ADR 0006): the leader writes them if nobody has, every
// replica reads them, and nothing ever overwrites what is there.

func assertionKeyGenerator(ns, name string) *controller.AssertionKeyGenerator {
	return &controller.AssertionKeyGenerator{
		Client:    k8sClient,
		Namespace: ns,
		Name:      name,
		Log:       logr.Discard(),
	}
}

func assertionKeyReader(ns, name string) *controller.AssertionKeys {
	return &controller.AssertionKeys{
		Client:    k8sClient,
		Namespace: ns,
		Name:      name,
		Log:       logr.Discard(),
	}
}

func TestTheLeaderWritesAssertionKeysEveryReplicaCanRead(t *testing.T) {
	ctx := context.Background()
	ns := newNamespace(t)

	generator := assertionKeyGenerator(ns, "gated-assertion-key")
	if !generator.NeedLeaderElection() {
		t.Error("the generator does not ask for the lease; every replica would decide on a different key")
	}
	if err := generator.Start(ctx); err != nil {
		t.Fatalf("Start() = %v", err)
	}

	// Two replicas, neither of them the leader.
	first, second := assertionKeyReader(ns, "gated-assertion-key"), assertionKeyReader(ns, "gated-assertion-key")
	if first.NeedLeaderElection() {
		t.Error("the reader waits for the lease; a follower could not vouch for anybody")
	}
	one, err := first.KeySet(ctx)
	if err != nil {
		t.Fatalf("KeySet() = %v", err)
	}
	two, err := second.KeySet(ctx)
	if err != nil {
		t.Fatalf("KeySet() = %v", err)
	}
	if err := first.Ready(nil); err != nil {
		t.Errorf("Ready() = %v after the keys were read", err)
	}

	// What one replica signs, a backend holding the other's key set
	// verifies.
	now := time.Now()
	signed, err := one.Sign(assertion.Claims{
		Issuer: "https://auth.example.com", Subject: "github:octocat",
		Audience: "shop.example.com", IssuedAt: now,
	})
	if err != nil {
		t.Fatalf("the key the leader wrote cannot sign: %v", err)
	}
	published, err := two.JWKS()
	if err != nil {
		t.Fatalf("JWKS() = %v", err)
	}
	if _, err := assertiontest.Verify(published, signed, assertiontest.Expect{
		Issuer: "https://auth.example.com", Audience: "shop.example.com", Now: now,
	}); err != nil {
		t.Errorf("an assertion signed on one replica does not verify against another's keys: %v", err)
	}
}

func TestExistingAssertionKeysAreNeverReplaced(t *testing.T) {
	ctx := context.Background()
	ns := newNamespace(t)

	generator := assertionKeyGenerator(ns, "gated-assertion-key")
	if err := generator.Start(ctx); err != nil {
		t.Fatalf("the first Start() = %v", err)
	}
	before := secretData(t, ns, "gated-assertion-key")

	// A restart, or a new leader.
	if err := generator.Start(ctx); err != nil {
		t.Fatalf("the second Start() = %v", err)
	}
	after := secretData(t, ns, "gated-assertion-key")
	if string(before[assertion.SigningKeyEntry]) != string(after[assertion.SigningKeyEntry]) {
		t.Error("the signing key changed on a restart; every backend would stop verifying until it fetched the keys again")
	}
}

// An operator rotating the keys writes the Secret by hand, and what they wrote
// is left exactly as it is — including when it cannot be used, which is said
// in the log and by the replicas never becoming ready, rather than mended.
func TestAssertionKeysPlacedByHandAreLeftAlone(t *testing.T) {
	ctx := context.Background()

	tests := map[string]struct {
		data     map[string][]byte
		wantRead bool
	}{
		"a key of their own, with the next one published": {
			data: map[string][]byte{
				assertion.SigningKeyEntry:    pemPrivate(t),
				assertion.PublishedKeysEntry: pemPrivate(t),
			},
			wantRead: true,
		},
		"something that is not a key": {
			data: map[string][]byte{assertion.SigningKeyEntry: []byte("0123456789abcdef0123456789abcdef")},
		},
		"nothing under the entry gated reads": {
			data: map[string][]byte{"something-else": pemPrivate(t)},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ns := newNamespace(t)
			placed := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "gated-assertion-key"},
				Type:       corev1.SecretTypeOpaque,
				Data:       tc.data,
			}
			if err := k8sClient.Create(ctx, placed); err != nil {
				t.Fatalf("placing the Secret: %v", err)
			}

			if err := assertionKeyGenerator(ns, "gated-assertion-key").Start(ctx); err != nil {
				t.Fatalf("Start() = %v", err)
			}
			after := secretData(t, ns, "gated-assertion-key")
			if len(after) != len(tc.data) {
				t.Errorf("the Secret now has %d entries, want the %d placed", len(after), len(tc.data))
			}
			for entry, value := range tc.data {
				if string(after[entry]) != string(value) {
					t.Errorf("the %q entry changed", entry)
				}
			}

			reader := assertionKeyReader(ns, "gated-assertion-key")
			_, err := reader.KeySet(ctx)
			switch {
			case tc.wantRead && err != nil:
				t.Errorf("KeySet() = %v", err)
			case !tc.wantRead && err == nil:
				t.Error("KeySet() = nil error for keys that cannot be used")
			case !tc.wantRead:
				if err := reader.Ready(nil); err == nil {
					t.Error("Ready() = nil with nothing to sign with; logged-in requests would be refused")
				}
			}
		})
	}
}

func TestReadingAssertionKeysThatAreNotThereYet(t *testing.T) {
	ctx := context.Background()
	ns := newNamespace(t)

	reader := assertionKeyReader(ns, "gated-assertion-key")
	if keys, err := reader.KeySet(ctx); err == nil {
		t.Fatalf("KeySet() = %v, nil; want an error before the keys exist", keys)
	}
	if err := reader.Ready(nil); err == nil {
		t.Error("Ready() = nil before the keys exist")
	}

	if err := assertionKeyGenerator(ns, "gated-assertion-key").Start(ctx); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	if _, err := reader.KeySet(ctx); err != nil {
		t.Errorf("KeySet() = %v once the keys exist", err)
	}
}

func secretData(t *testing.T, ns, name string) map[string][]byte {
	t.Helper()
	var secret corev1.Secret
	if err := k8sClient.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &secret); err != nil {
		t.Fatalf("reading Secret %s/%s: %v", ns, name, err)
	}
	return secret.Data
}

func pemPrivate(t *testing.T) []byte {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
