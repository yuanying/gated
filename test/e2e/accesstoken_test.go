//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	gatev1alpha1 "github.com/yuanying/gated/internal/apis/gate/v1alpha1"
)

// A token issued by an AccessToken is accepted both as a bearer credential
// and in the password field of BASIC authentication, and the decision that
// follows is the same one a browser gets (ADR 0004).
func TestAccessTokenOpensBothDoors(t *testing.T) {
	ctx := testContext(t, settleTimeout)

	chain := certificateFor(t, ctx, "token-tls")
	client := caller(t, issuingRoots(t, chain))

	applyObject(t, ctx, role("token-readers", "token", anyMethod()))
	applyObject(t, ctx, binding("token-readers", "token-readers", "github:robot"))

	applyObject(t, ctx, &gatev1alpha1.AccessToken{
		ObjectMeta: metav1.ObjectMeta{Namespace: appNamespace, Name: "robot"},
		Spec:       gatev1alpha1.AccessTokenSpec{Subject: "github:robot"},
	})
	token := issuedToken(t, ctx, "robot")

	waitFor(t, ctx, "the NetworkRole never took effect", func() bool {
		status, _ := get(t, client, https(tokenHost, "/"), nil)
		return status == http.StatusUnauthorized
	})

	t.Run("no credential is refused", func(t *testing.T) {
		// Not a redirect: a program handed a login page follows it and
		// reports the HTML as though it were the answer (ADR 0018).
		status, _ := get(t, client, https(tokenHost, "/"), nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("an anonymous caller was answered %d, want 401", status)
		}
	})

	t.Run("Authorization: Bearer", func(t *testing.T) {
		header := http.Header{"Authorization": {"Bearer " + token}}
		status, body := get(t, client, https(tokenHost, "/api"), header)
		if status != http.StatusOK {
			t.Fatalf("the bearer token was answered %d, want 200\n%s", status, body)
		}
		if !fromBackend(body) {
			t.Fatalf("the bearer token did not reach the application:\n%s", body)
		}
	})

	t.Run("the password field of BASIC authentication", func(t *testing.T) {
		// The user name is not read, so anything at all goes in it
		// (ADR 0022). "docker login" is the client this door exists for.
		status, body := request(t, client, http.MethodGet, https(tokenHost, "/v2/"), nil,
			&basic{user: "anything-at-all", password: token})
		if status != http.StatusOK {
			t.Fatalf("the token in the password field was answered %d, want 200\n%s", status, body)
		}
		if !fromBackend(body) {
			t.Fatalf("the token in the password field did not reach the application:\n%s", body)
		}
	})

	t.Run("a token that was never issued is refused", func(t *testing.T) {
		header := http.Header{"Authorization": {"Bearer " + gatev1alpha1.TokenPrefix + "not-a-real-token"}}
		status, _ := get(t, client, https(tokenHost, "/api"), header)
		if status != http.StatusUnauthorized {
			t.Fatalf("an invented token was answered %d, want 401", status)
		}
	})
}

// issuedToken waits for the controller to mint a token and returns its value.
//
// The value is read from the Secret, which is the only place it exists: the
// status carries a digest, and a digest is not something to present.
func issuedToken(t *testing.T, ctx context.Context, name string) string {
	t.Helper()

	var value string
	key := types.NamespacedName{Namespace: appNamespace, Name: name}
	err := poll(ctx, settleTimeout, func(ctx context.Context) (bool, error) {
		var token gatev1alpha1.AccessToken
		if err := k8s.Get(ctx, key, &token); err != nil {
			return false, nil
		}
		if token.Status.SecretRef == nil || token.Status.TokenHash == "" {
			return false, nil
		}

		var secret corev1.Secret
		secretKey := types.NamespacedName{Namespace: appNamespace, Name: token.Status.SecretRef.Name}
		if err := k8s.Get(ctx, secretKey, &secret); err != nil {
			return false, nil
		}
		raw := secret.Data[gatev1alpha1.TokenSecretKey]
		if len(raw) == 0 {
			return false, nil
		}
		value = string(raw)
		return true, nil
	})
	if err != nil {
		t.Fatalf("AccessToken %s was never issued: %v", key, err)
	}
	return value
}
