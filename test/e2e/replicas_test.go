//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	"github.com/yuanying/gated/internal/acme/http01"
	"github.com/yuanying/gated/internal/proxy"
)

// Several replicas order one certificate between them, and any of them can
// answer an ACME challenge.
//
// These are two consequences of the same decision (ADR 0006): issuing is the
// leader's job because two replicas ordering means two orders, and answering
// is everybody's job because the validation server arrives wherever the load
// balancer sends it. Testing one without the other would miss the point —
// limiting issuance is only safe because answering was not limited with it.
func TestReplicasShareTheWork(t *testing.T) {
	ctx := testContext(t, settleTimeout)

	pods := gatedPods(t, ctx)
	if len(pods) < 2 {
		t.Fatalf("found %d gated replicas, want at least 2; the scenario is about more than one", len(pods))
	}

	// Certificates for every host were obtained by the time the tests got
	// here, and there is only ever one Lease.
	certificateFor(t, ctx, "open-tls")

	t.Run("exactly one replica holds the lease", func(t *testing.T) {
		var lease coordinationv1.Lease
		key := types.NamespacedName{Namespace: gatedNamespace, Name: "gated-leader-election"}
		if err := k8s.Get(ctx, key, &lease); err != nil {
			t.Fatalf("reading the leader election Lease %s: %v", key, err)
		}
		if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" {
			t.Fatalf("the Lease %s names no leader", key)
		}

		holder := *lease.Spec.HolderIdentity
		found := false
		for _, p := range pods {
			if strings.HasPrefix(holder, p.Name) {
				found = true
			}
		}
		if !found {
			t.Fatalf("the Lease is held by %q, which is none of the replicas", holder)
		}
	})

	t.Run("only the leader ordered a certificate", func(t *testing.T) {
		ordering := 0
		for _, p := range pods {
			logs, err := podLogs(ctx, p.Namespace, p.Name)
			if err != nil {
				t.Fatalf("reading the log of %s: %v", p.Name, err)
			}
			if strings.Contains(logs, "ordering a certificate") {
				ordering++
			}
		}
		if ordering != 1 {
			t.Fatalf("%d of %d replicas ordered certificates, want exactly 1", ordering, len(pods))
		}
	})

	t.Run("every replica answers a challenge", func(t *testing.T) {
		// Published the way the leader publishes one: into the Secret
		// every replica reads (ADR 0015). Reaching a replica directly
		// is what makes the answer attributable to that replica rather
		// than to whichever one the Service happened to choose.
		token := "e2e-challenge-token"
		keyAuthorization := "e2e-challenge-token.e2e-account-thumbprint"
		publishChallenge(t, ctx, token, keyAuthorization)

		for _, pod := range pods {
			addr := forward(t, ctx, pod, 8080)
			client := &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, network, addr)
					},
				},
				CheckRedirect: func(*http.Request, []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			target := "http://" + openHost + proxy.ChallengePath + token
			var status int
			var body string
			// The replicas read the shared set on a timer, so a
			// challenge published a moment ago is answered a
			// moment later.
			waitFor(t, ctx, fmt.Sprintf("%s never answered the challenge", pod.Name), func() bool {
				status, body = get(t, client, target, nil)
				return status == http.StatusOK
			})
			if strings.TrimSpace(body) != keyAuthorization {
				t.Fatalf("%s answered the challenge with %q, want %q", pod.Name, body, keyAuthorization)
			}
		}
	})
}

// publishChallenge writes one outstanding challenge into the Secret the
// replicas share, and takes it away again when the test ends.
func publishChallenge(t *testing.T, ctx context.Context, token, keyAuthorization string) {
	t.Helper()

	key := types.NamespacedName{Namespace: gatedNamespace, Name: http01.DefaultSecretName}
	edit := func(apply func(map[string]http01.Entry)) error {
		return retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var secret corev1.Secret
			if err := k8s.Get(ctx, key, &secret); err != nil {
				return err
			}
			entries := map[string]http01.Entry{}
			if raw := secret.Data[http01.ChallengesEntry]; len(raw) > 0 {
				if err := json.Unmarshal(raw, &entries); err != nil {
					return err
				}
			}
			apply(entries)
			encoded, err := json.Marshal(entries)
			if err != nil {
				return err
			}
			if secret.Data == nil {
				secret.Data = map[string][]byte{}
			}
			secret.Data[http01.ChallengesEntry] = encoded
			return k8s.Update(ctx, &secret)
		})
	}

	// The Secret exists because certificates were issued before this test
	// ran; create it if a run somehow got here without one.
	var secret corev1.Secret
	if err := k8s.Get(ctx, key, &secret); err != nil {
		if createErr := k8s.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{http01.ChallengesEntry: []byte("{}")},
		}); createErr != nil {
			t.Fatalf("preparing the shared challenge Secret %s: %v (get: %v)", key, createErr, err)
		}
	}

	if err := edit(func(entries map[string]http01.Entry) {
		entries[token] = http01.Entry{Host: openHost, KeyAuthorization: keyAuthorization}
	}); err != nil {
		t.Fatalf("publishing a challenge into %s: %v", key, err)
	}
	t.Cleanup(func() {
		_ = edit(func(entries map[string]http01.Entry) { delete(entries, token) })
	})
}
