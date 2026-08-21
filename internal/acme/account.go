package acme

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AccountKeyEntry is the key the account's private key is stored under.
const AccountKeyEntry = "account.key"

// AccountStore hands out the ACME account key.
//
// One key identifies gated to the directory for the life of the installation.
// Losing it means the CA no longer recognises the account, and the issuance
// history that goes with it, so it outlives any single Pod.
type AccountStore interface {
	// AccountKey returns the account key, creating and storing one the
	// first time it is asked.
	AccountKey(ctx context.Context) (crypto.Signer, error)
}

// SecretAccountStore keeps the account key in a Secret.
//
// A Secret rather than a volume: every replica has to reach the same key, and
// state shared between replicas is expressed as a Kubernetes object rather
// than as anything the replicas say to each other (ADR 0006).
type SecretAccountStore struct {
	// Client reads and writes the Secret. It must not be backed by a cache
	// restricted to TLS Secrets, or this Opaque one reads as absent.
	Client client.Client
	// Namespace and Name locate the Secret, spelled out in full because
	// gated reaches outside its own namespace (ADR 0009).
	Namespace string
	Name      string
	// Log records the one event worth seeing: a key being created.
	Log logr.Logger

	mu  sync.Mutex
	key crypto.Signer
}

// AccountKey reads the stored key, generating one if the Secret does not exist
// yet.
//
// Two replicas racing to create the Secret is not a problem: the loser is told
// the Secret already exists and reads the winner's key. It is a problem to
// overwrite an existing one, so nothing here ever updates a Secret that is
// already there.
func (s *SecretAccountStore) AccountKey(ctx context.Context) (crypto.Signer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		return s.key, nil
	}
	if s.Client == nil || s.Namespace == "" || s.Name == "" {
		return nil, errors.New("the ACME account Secret is not configured")
	}

	key, err := s.read(ctx)
	if err == nil {
		s.key = key
		return key, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, err
	}

	created, err := newKey()
	if err != nil {
		return nil, fmt.Errorf("generating an ACME account key: %w", err)
	}
	pemKey, err := encodeKey(created)
	if err != nil {
		return nil, err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: s.Namespace,
			Name:      s.Name,
			Labels:    map[string]string{ManagedByLabel: ManagedByValue},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{AccountKeyEntry: pemKey},
	}
	if err := s.Client.Create(ctx, secret); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("creating the ACME account Secret %s/%s: %w", s.Namespace, s.Name, err)
		}
		// Somebody got there first. Their key is the account.
		key, err := s.read(ctx)
		if err != nil {
			return nil, err
		}
		s.key = key
		return key, nil
	}

	s.Log.Info("created an ACME account key", "namespace", s.Namespace, "secret", s.Name)
	s.key = created
	return created, nil
}

// read loads the key out of the Secret, reporting a not-found error the caller
// can tell apart from a Secret that exists but holds nothing usable.
func (s *SecretAccountStore) read(ctx context.Context) (crypto.Signer, error) {
	var secret corev1.Secret
	key := types.NamespacedName{Namespace: s.Namespace, Name: s.Name}
	if err := s.Client.Get(ctx, key, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, err
		}
		return nil, fmt.Errorf("reading the ACME account Secret %s: %w", key, err)
	}
	data := secret.Data[AccountKeyEntry]
	if len(data) == 0 {
		return nil, fmt.Errorf("the ACME account Secret %s has no %q entry", key, AccountKeyEntry)
	}
	signer, err := decodeKey(data)
	if err != nil {
		return nil, fmt.Errorf("the ACME account Secret %s: %w", key, err)
	}
	return signer, nil
}

// encodeKey renders a private key as PKCS#8 PEM.
func encodeKey(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshalling the account key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// decodeKey reads a private key back, accepting the three encodings a key
// written by another tool is likely to be in.
func decodeKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("the account key is not PEM")
	}
	var (
		parsed any
		err    error
	)
	switch block.Type {
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("the account key cannot be parsed: %w", err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("the account key is a %T, which cannot sign", parsed)
	}
	return signer, nil
}
