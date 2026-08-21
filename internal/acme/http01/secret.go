package http01

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/yuanying/gated/internal/acme"
)

// ChallengesEntry is the key inside the Secret the outstanding challenges are
// stored under, as a JSON object keyed by token.
//
// One entry rather than one Secret key per token: a token is unguessable
// base64 and reads terribly as a key, and a single document makes a
// concurrent update a plain read-modify-write.
const ChallengesEntry = "challenges"

// DefaultSecretName is the Secret the challenges live in. Only the namespace
// is configurable (ADR 0009); the name is gated's own and not a property of
// the deployment.
const DefaultSecretName = "gated-acme-challenges"

// SecretStore keeps the outstanding challenges in one Secret.
type SecretStore struct {
	// Client reads and writes the Secret. It must not be backed by a cache
	// restricted to TLS Secrets, or this Opaque one reads as absent.
	Client client.Client
	// Namespace is where the Secret lives. Required.
	Namespace string
	// Name is the Secret's name; empty uses DefaultSecretName.
	Name string
}

// Challenges returns every outstanding challenge.
//
// A Secret that is not there yet is not an error: it means no order is in
// flight, which is the ordinary state.
func (s *SecretStore) Challenges(ctx context.Context) (map[string]Entry, error) {
	secret, err := s.get(ctx)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return map[string]Entry{}, nil
		}
		return nil, err
	}
	return decodeEntries(secret)
}

// Put records one challenge, leaving the others in place.
func (s *SecretStore) Put(ctx context.Context, token string, entry Entry) error {
	return s.update(ctx, func(entries map[string]Entry) { entries[token] = entry })
}

// Delete withdraws one challenge, tolerating one that is already gone.
func (s *SecretStore) Delete(ctx context.Context, token string) error {
	return s.update(ctx, func(entries map[string]Entry) { delete(entries, token) })
}

// update applies a change to the stored set, creating the Secret on first use
// and retrying the conflicts a concurrent writer causes.
func (s *SecretStore) update(ctx context.Context, apply func(map[string]Entry)) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		secret, err := s.get(ctx)
		if apierrors.IsNotFound(err) {
			entries := map[string]Entry{}
			apply(entries)
			data, err := encodeEntries(entries)
			if err != nil {
				return err
			}
			created := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: s.Namespace,
					Name:      s.name(),
					Labels:    map[string]string{acme.ManagedByLabel: acme.ManagedByValue},
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{ChallengesEntry: data},
			}
			if err := s.Client.Create(ctx, created); err != nil {
				if apierrors.IsAlreadyExists(err) {
					// Somebody created it between the read and
					// the write. Retry as an update.
					return apierrors.NewConflict(
						schemaResource(), s.name(), err)
				}
				return fmt.Errorf("creating the challenge Secret %s/%s: %w", s.Namespace, s.name(), err)
			}
			return nil
		}
		if err != nil {
			return err
		}

		entries, err := decodeEntries(secret)
		if err != nil {
			// Unreadable content is replaced rather than preserved:
			// what is in there is at worst a challenge nobody is
			// waiting on any more.
			entries = map[string]Entry{}
		}
		apply(entries)
		data, err := encodeEntries(entries)
		if err != nil {
			return err
		}
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		secret.Data[ChallengesEntry] = data
		if err := s.Client.Update(ctx, secret); err != nil {
			if apierrors.IsConflict(err) {
				return err
			}
			return fmt.Errorf("updating the challenge Secret %s/%s: %w", s.Namespace, s.name(), err)
		}
		return nil
	})
}

func (s *SecretStore) get(ctx context.Context) (*corev1.Secret, error) {
	var secret corev1.Secret
	key := types.NamespacedName{Namespace: s.Namespace, Name: s.name()}
	if err := s.Client.Get(ctx, key, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, err
		}
		return nil, fmt.Errorf("reading the challenge Secret %s: %w", key, err)
	}
	return &secret, nil
}

func (s *SecretStore) name() string {
	if s.Name != "" {
		return s.Name
	}
	return DefaultSecretName
}

func decodeEntries(secret *corev1.Secret) (map[string]Entry, error) {
	data := secret.Data[ChallengesEntry]
	if len(data) == 0 {
		return map[string]Entry{}, nil
	}
	entries := map[string]Entry{}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("the %q entry of Secret %s/%s is not readable: %w",
			ChallengesEntry, secret.Namespace, secret.Name, err)
	}
	return entries, nil
}

func encodeEntries(entries map[string]Entry) ([]byte, error) {
	// Marshalling a map sorts its keys, so an unchanged set of challenges
	// produces identical bytes and no spurious update.
	data, err := json.Marshal(entries)
	if err != nil {
		return nil, fmt.Errorf("encoding the outstanding challenges: %w", err)
	}
	return data, nil
}

// schemaResource names Secrets for the conflict error raised when a create
// loses the race, so that RetryOnConflict recognises it.
func schemaResource() schema.GroupResource {
	return schema.GroupResource{Group: "", Resource: "secrets"}
}
