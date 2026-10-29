//go:build envtest

package envtest_test

import (
	"context"
	"slices"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/yuanying/gated/internal/controller"
	"github.com/yuanying/gated/internal/serviceaccount"
)

// The TokenReview is the one thing gated asks the API server about a
// ServiceAccount token (ADR 0039). What the answer means is judged elsewhere,
// by a pure function; what is checked here is that the question is asked the
// way the API server understands it, and the answer read back the way it
// gives it.
func TestTheAPIServerIsAskedAboutAServiceAccountToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	ns := newNamespace(t)
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "assistant"}}
	if err := k8sClient.Create(ctx, sa); err != nil {
		t.Fatalf("creating the ServiceAccount: %v", err)
	}

	const gatedAudience = "https://auth.example.com"
	tokenFor := func(audience string) string {
		t.Helper()
		request := &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{audience},
			ExpirationSeconds: ptr.To[int64](600),
		}}
		if err := k8sClient.SubResource("token").Create(ctx, sa, request); err != nil {
			t.Fatalf("requesting a token for %q: %v", audience, err)
		}
		return request.Status.Token
	}

	reviewer := &controller.TokenReviewer{Client: k8sClient}

	t.Run("a token for gated", func(t *testing.T) {
		review, err := reviewer.Review(ctx, tokenFor(gatedAudience), gatedAudience)
		if err != nil {
			t.Fatalf("Review() = %v", err)
		}
		want := "system:serviceaccount:" + ns + ":assistant"
		if !review.Authenticated || review.Username != want || !slices.Contains(review.Audiences, gatedAudience) {
			t.Errorf("Review() = %+v, want %s authenticated for %s", review, want, gatedAudience)
		}
		if subject, reason := serviceaccount.Judge(review, gatedAudience); reason != serviceaccount.Accepted || subject != want {
			t.Errorf("Judge() = %q, %q; want %q accepted", subject, reason, want)
		}
	})

	t.Run("a token for somebody else", func(t *testing.T) {
		review, err := reviewer.Review(ctx, tokenFor("a2a"), gatedAudience)
		if err != nil {
			t.Fatalf("Review() = %v", err)
		}
		if review.Authenticated {
			t.Errorf("a token for a2a was authenticated for gated: %+v", review)
		}
		if _, reason := serviceaccount.Judge(review, gatedAudience); reason == serviceaccount.Accepted {
			t.Error("a token for a2a was accepted")
		}
	})

	t.Run("an invented token", func(t *testing.T) {
		review, err := reviewer.Review(ctx, "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOlsiaHR0cHM6Ly9hdXRoLmV4YW1wbGUuY29tIl19.c2ln", gatedAudience)
		if err != nil {
			t.Fatalf("Review() = %v", err)
		}
		if review.Authenticated {
			t.Errorf("an invented token was authenticated: %+v", review)
		}
	})
}
