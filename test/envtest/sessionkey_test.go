//go:build envtest

package envtest_test

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/yuanying/gated/internal/authn"
	"github.com/yuanying/gated/internal/controller"
)

// The signing key is the one piece of shared state authentication needs
// (ADR 0006): the leader writes it, every replica reads it, and every replica
// then verifies what any other one signed.
//
// These run against a real API server because what is being checked is the
// interaction with it — a create that loses a race, a Secret already there,
// an entry that is not what it should be. None of that is visible against a
// fake client.

func sessionKeyGenerator(t *testing.T, ns, name string) *controller.SessionKeyGenerator {
	t.Helper()
	return &controller.SessionKeyGenerator{
		Client:    k8sClient,
		Namespace: ns,
		Name:      name,
		Log:       logr.Discard(),
	}
}

func sessionKeyReader(t *testing.T, ns, name string) *controller.SecretEntry {
	t.Helper()
	return &controller.SecretEntry{
		Client:    k8sClient,
		Namespace: ns,
		Name:      name,
		Key:       authn.SessionKeySecretEntry,
		What:      "the session signing key",
		Log:       logr.Discard(),
	}
}

// TestTheLeaderWritesAKeyEveryReplicaCanRead is the arrangement ADR 0006
// describes, with one replica generating and another reading what it wrote.
func TestTheLeaderWritesAKeyEveryReplicaCanRead(t *testing.T) {
	ctx := context.Background()
	ns := newNamespace(t)

	generator := sessionKeyGenerator(t, ns, "gated-session-key")
	if !generator.NeedLeaderElection() {
		t.Error("the generator does not ask for the lease; every replica would decide on a different key (ADR 0006)")
	}
	if err := generator.Start(ctx); err != nil {
		t.Fatalf("Start() = %v", err)
	}

	// A replica that never wins the lease reads what the leader wrote.
	follower := sessionKeyReader(t, ns, "gated-session-key")
	if follower.NeedLeaderElection() {
		t.Error("the reader waits for the lease; a follower that cannot verify a cookie logs everybody out")
	}
	key, err := follower.Value(ctx)
	if err != nil {
		t.Fatalf("Value() = %v", err)
	}
	if len(key) < authn.MinKeySize {
		t.Fatalf("the key is %d bytes, want at least %d", len(key), authn.MinKeySize)
	}
	if err := follower.Ready(nil); err != nil {
		t.Errorf("Ready() = %v after the key was read", err)
	}

	// And what one replica signs, another verifies.
	now := time.Now()
	signed, err := authn.Sign(key, authn.Token{
		Kind: authn.KindSession, Subject: "github:octocat", Audience: "shop.example.com",
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("the key the leader wrote cannot sign: %v", err)
	}
	if _, err := authn.Verify(key, signed, authn.Expect{
		Kind: authn.KindSession, Audience: "shop.example.com", Now: now,
	}); err != nil {
		t.Errorf("a session signed with the shared key does not verify: %v", err)
	}
}

// TestAnExistingKeyIsNeverReplaced is the property that keeps a restart from
// logging everybody out. Replacing the key revokes every session at once
// (ADR 0003), which is something an operator does on purpose.
func TestAnExistingKeyIsNeverReplaced(t *testing.T) {
	ctx := context.Background()
	ns := newNamespace(t)

	generator := sessionKeyGenerator(t, ns, "gated-session-key")
	if err := generator.Start(ctx); err != nil {
		t.Fatalf("the first Start() = %v", err)
	}
	first, err := sessionKeyReader(t, ns, "gated-session-key").Value(ctx)
	if err != nil {
		t.Fatalf("Value() = %v", err)
	}

	// A restart, or a new leader.
	if err := generator.Start(ctx); err != nil {
		t.Fatalf("the second Start() = %v", err)
	}
	second, err := sessionKeyReader(t, ns, "gated-session-key").Value(ctx)
	if err != nil {
		t.Fatalf("Value() = %v", err)
	}
	if string(first) != string(second) {
		t.Error("the key changed on a restart; every session in the installation would have ended")
	}
}

// TestAKeyPlacedByHandIsLeftAlone covers an operator who put the Secret there
// themselves, including the case where what they put there is not usable.
func TestAKeyPlacedByHandIsLeftAlone(t *testing.T) {
	ctx := context.Background()

	tests := map[string]struct {
		data      map[string][]byte
		wantValue string
		wantRead  bool
	}{
		"a key of their own": {
			data:      map[string][]byte{authn.SessionKeySecretEntry: []byte("0123456789abcdef0123456789abcdef")},
			wantValue: "0123456789abcdef0123456789abcdef",
			wantRead:  true,
		},
		"something too short to sign with": {
			data:      map[string][]byte{authn.SessionKeySecretEntry: []byte("short")},
			wantValue: "short",
			wantRead:  true,
		},
		"nothing under the entry gated reads": {
			data: map[string][]byte{"something-else": []byte("0123456789abcdef0123456789abcdef")},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ns := newNamespace(t)
			placed := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "gated-session-key"},
				Type:       corev1.SecretTypeOpaque,
				Data:       tc.data,
			}
			if err := k8sClient.Create(ctx, placed); err != nil {
				t.Fatalf("placing the Secret: %v", err)
			}

			if err := sessionKeyGenerator(t, ns, "gated-session-key").Start(ctx); err != nil {
				t.Fatalf("Start() = %v", err)
			}

			var after corev1.Secret
			if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "gated-session-key"}, &after); err != nil {
				t.Fatalf("reading the Secret back: %v", err)
			}
			if got := string(after.Data[authn.SessionKeySecretEntry]); got != tc.wantValue {
				t.Errorf("the entry is now %q, want %q left as it was", got, tc.wantValue)
			}

			reader := sessionKeyReader(t, ns, "gated-session-key")
			value, err := reader.Value(ctx)
			switch {
			case tc.wantRead && err != nil:
				t.Errorf("Value() = %v", err)
			case tc.wantRead && string(value) != tc.wantValue:
				t.Errorf("Value() = %q, want %q", value, tc.wantValue)
			case !tc.wantRead && err == nil:
				t.Errorf("Value() = %q, want an error", value)
			case !tc.wantRead:
				if err := reader.Ready(nil); err == nil {
					t.Error("Ready() = nil with nothing read; the replica would treat everybody as anonymous")
				}
			}
		})
	}
}

// TestReadingAKeyThatIsNotThereYet is what a follower sees before the leader
// has written one: an error rather than an empty key, so that nothing signs
// with nothing.
func TestReadingAKeyThatIsNotThereYet(t *testing.T) {
	ctx := context.Background()
	ns := newNamespace(t)

	reader := sessionKeyReader(t, ns, "gated-session-key")
	if value, err := reader.Value(ctx); err == nil {
		t.Fatalf("Value() = %q, nil; want an error before the key exists", value)
	}
	if err := reader.Ready(nil); err == nil {
		t.Error("Ready() = nil before the key exists")
	}

	if err := sessionKeyGenerator(t, ns, "gated-session-key").Start(ctx); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	if _, err := reader.Value(ctx); err != nil {
		t.Errorf("Value() = %v once the key exists", err)
	}
}
