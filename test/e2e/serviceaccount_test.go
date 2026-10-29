//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/yuanying/gated/internal/assertion/assertiontest"
)

// A workload in the cluster calls through gated with its ServiceAccount's
// token, and is decided on exactly as a person who logged in would be
// (ADR 0039). The tokens are the API server's own, minted as
// `kubectl create token --audience` would mint them, and gated asks the same
// API server about them with the permission the manifests grant it.
func TestAServiceAccountTokenIsCheckedWithTheAPIServer(t *testing.T) {
	ctx := testContext(t, settleTimeout)

	saChain := certificateFor(t, ctx, "serviceaccount-tls")
	certificateFor(t, ctx, "auth-tls")
	certificateFor(t, ctx, "open-tls")
	roots := issuingRoots(t, saChain)
	client := caller(t, roots)

	allowed := serviceAccount(t, ctx, "allowed-caller")
	other := serviceAccount(t, ctx, "other-caller")

	applyObject(t, ctx, role("sa-callers", "serviceaccount", anyMethod()))
	applyObject(t, ctx, binding("sa-callers", "sa-callers", "system:serviceaccount:"+appNamespace+":allowed-caller"))

	waitFor(t, ctx, "the NetworkRole never took effect", func() bool {
		status, _ := get(t, client, https(saHost, "/"), nil)
		return status == http.StatusUnauthorized
	})

	_, jwks := get(t, client, https(authHost, "/__gated/jwks.json"), nil)

	t.Run("a bound ServiceAccount is let through", func(t *testing.T) {
		token := tokenFor(t, ctx, allowed, serviceAccountAudience)
		status, body := get(t, client, https(saHost, "/api"), bearer(token))
		if status != http.StatusOK || !fromBackend(body) {
			t.Fatalf("the ServiceAccount was answered %d, want 200 from the application\n%s", status, body)
		}
		// Spent by gated, never handed on (ADR 0022).
		if got := echoed(body, "Authorization"); len(got) != 0 {
			t.Errorf("the application was handed the token: %v", got)
		}
		signed := echoed(body, "Gated-Assertion")
		if len(signed) != 1 {
			t.Fatalf("the application saw %d Gated-Assertion headers, want 1:\n%s", len(signed), body)
		}
		claims, err := assertiontest.Verify([]byte(jwks), signed[0], assertiontest.Expect{
			Issuer:   "https://" + authHost,
			Audience: saHost,
			Now:      time.Now(),
		})
		if err != nil {
			t.Fatalf("the assertion does not verify against the published keys: %v", err)
		}
		if want := "system:serviceaccount:" + appNamespace + ":allowed-caller"; claims.Subject != want {
			t.Errorf("the assertion vouches for %q, want %q", claims.Subject, want)
		}
	})

	t.Run("a ServiceAccount nothing grants to is refused", func(t *testing.T) {
		token := tokenFor(t, ctx, other, serviceAccountAudience)
		if status, body := get(t, client, https(saHost, "/api"), bearer(token)); status != http.StatusForbidden {
			t.Fatalf("an unbound ServiceAccount was answered %d, want 403\n%s", status, body)
		}
	})

	t.Run("a token for another audience is nobody", func(t *testing.T) {
		token := tokenFor(t, ctx, allowed, "a2a")
		if status, body := get(t, client, https(saHost, "/api"), bearer(token)); status != http.StatusUnauthorized {
			t.Fatalf("a token for a2a was answered %d, want 401\n%s", status, body)
		}
	})

	t.Run("a token for another audience reaches the application as it came", func(t *testing.T) {
		// What fraction-agents checks for itself: gated does not
		// spend it, so it is not gated's to take away.
		token := tokenFor(t, ctx, allowed, "a2a")
		status, body := get(t, client, https(openHost, "/api"), bearer(token))
		if status != http.StatusOK || !fromBackend(body) {
			t.Fatalf("an unprotected host answered %d, want 200 from the application\n%s", status, body)
		}
		if got := echoed(body, "Authorization"); len(got) != 1 || got[0] != "Bearer "+token {
			t.Errorf("the application was handed Authorization %v, want the token as it came", got)
		}
		if got := echoed(body, "Gated-Assertion"); len(got) != 0 {
			t.Errorf("a request nobody was authenticated for carried an assertion: %v", got)
		}
	})
}

// serviceAccount creates one in the namespace the applications run in.
func serviceAccount(t *testing.T, ctx context.Context, name string) *corev1.ServiceAccount {
	t.Helper()
	sa := &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"},
		ObjectMeta: metav1.ObjectMeta{Namespace: appNamespace, Name: name},
	}
	applyObject(t, ctx, sa)
	return sa
}

// tokenFor asks the API server for a token, as `kubectl create token` does.
func tokenFor(t *testing.T, ctx context.Context, sa *corev1.ServiceAccount, audience string) string {
	t.Helper()
	request := &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{
		Audiences:         []string{audience},
		ExpirationSeconds: ptr.To[int64](600),
	}}
	if err := k8s.SubResource("token").Create(ctx, sa, request); err != nil {
		t.Fatalf("requesting a token for %s with audience %q: %v", sa.Name, audience, err)
	}
	return request.Status.Token
}

func bearer(token string) http.Header {
	return http.Header{"Authorization": {"Bearer " + token}}
}
