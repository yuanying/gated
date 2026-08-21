//go:build envtest

package envtest_test

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	gatedacme "github.com/yuanying/gated/internal/acme"
	"github.com/yuanying/gated/internal/acme/http01"
)

// TestAccountKeyIsCreatedOnce covers the key that identifies gated to the CA
// for the life of the installation (ADR 0005): created on first use, and never
// replaced afterwards.
func TestAccountKeyIsCreatedOnce(t *testing.T) {
	ns := newNamespace(t)
	store := &gatedacme.SecretAccountStore{Client: k8sClient, Namespace: ns, Name: "acme-account"}

	key, err := store.AccountKey(context.Background())
	if err != nil {
		t.Fatalf("AccountKey() = %v", err)
	}
	if key == nil {
		t.Fatal("AccountKey() returned no key")
	}

	var secret corev1.Secret
	if err := k8sClient.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "acme-account"}, &secret); err != nil {
		t.Fatalf("the account Secret was not written: %v", err)
	}
	stored := secret.Data[gatedacme.AccountKeyEntry]
	if len(stored) == 0 {
		t.Fatalf("the account Secret has no %q entry", gatedacme.AccountKeyEntry)
	}

	// A second process, with no memory of the first, has to arrive at the
	// same key rather than register a new account.
	other := &gatedacme.SecretAccountStore{Client: k8sClient, Namespace: ns, Name: "acme-account"}
	if _, err := other.AccountKey(context.Background()); err != nil {
		t.Fatalf("AccountKey() from a second reader = %v", err)
	}
	if err := k8sClient.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "acme-account"}, &secret); err != nil {
		t.Fatalf("reading the account Secret again: %v", err)
	}
	if string(secret.Data[gatedacme.AccountKeyEntry]) != string(stored) {
		t.Error("the account key was replaced by a second reader")
	}
}

func TestAccountKeyRejectsUnreadableMaterial(t *testing.T) {
	ns := newNamespace(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "acme-account"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{gatedacme.AccountKeyEntry: []byte("not a key")},
	}
	if err := k8sClient.Create(context.Background(), secret); err != nil {
		t.Fatalf("creating the Secret: %v", err)
	}

	store := &gatedacme.SecretAccountStore{Client: k8sClient, Namespace: ns, Name: "acme-account"}
	if _, err := store.AccountKey(context.Background()); err == nil {
		t.Error("AccountKey() = nil, want a complaint rather than a silently regenerated account")
	}
}

// TestChallengeSecretRoundTrip covers the state every replica reads to answer
// an HTTP-01 challenge (ADR 0006).
func TestChallengeSecretRoundTrip(t *testing.T) {
	ns := newNamespace(t)
	store := &http01.SecretStore{Client: k8sClient, Namespace: ns}
	ctx := context.Background()

	// Nothing in flight is the ordinary state, not an error.
	entries, err := store.Challenges(ctx)
	if err != nil {
		t.Fatalf("Challenges() before anything was published = %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Challenges() = %v, want none", entries)
	}

	if err := store.Put(ctx, "token-one", http01.Entry{Host: "app.example.com", KeyAuthorization: "one.auth"}); err != nil {
		t.Fatalf("Put() = %v", err)
	}
	if err := store.Put(ctx, "token-two", http01.Entry{Host: "api.example.com", KeyAuthorization: "two.auth"}); err != nil {
		t.Fatalf("Put() = %v", err)
	}

	entries, err = store.Challenges(ctx)
	if err != nil {
		t.Fatalf("Challenges() = %v", err)
	}
	if got := entries["token-one"]; got.KeyAuthorization != "one.auth" || got.Host != "app.example.com" {
		t.Errorf("token-one = %+v, want the published entry", got)
	}
	if got := entries["token-two"]; got.KeyAuthorization != "two.auth" {
		t.Errorf("token-two = %+v, want the published entry", got)
	}

	var secret corev1.Secret
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: http01.DefaultSecretName}, &secret); err != nil {
		t.Fatalf("the challenge Secret was not written: %v", err)
	}
	if secret.Type != corev1.SecretTypeOpaque {
		t.Errorf("Secret type = %q, want %q", secret.Type, corev1.SecretTypeOpaque)
	}

	// Withdrawing one challenge leaves the other answerable, which matters
	// while an order for several hosts is still in flight.
	if err := store.Delete(ctx, "token-one"); err != nil {
		t.Fatalf("Delete() = %v", err)
	}
	entries, err = store.Challenges(ctx)
	if err != nil {
		t.Fatalf("Challenges() after Delete = %v", err)
	}
	if _, ok := entries["token-one"]; ok {
		t.Error("the withdrawn challenge is still published")
	}
	if _, ok := entries["token-two"]; !ok {
		t.Error("withdrawing one challenge removed the other")
	}

	// Withdrawing something that was never there is what an order failing
	// half way through looks like.
	if err := store.Delete(ctx, "never-published"); err != nil {
		t.Errorf("Delete() of an absent challenge = %v, want nil", err)
	}
}
