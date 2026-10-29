package controller

import (
	"context"
	"fmt"

	authenticationv1 "k8s.io/api/authentication/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/yuanying/gated/internal/serviceaccount"
)

// TokenReviewer asks the API server about a ServiceAccount token (ADR 0039).
//
// It is the Kubernetes side of serviceaccount.Reviewer and does nothing but
// translate: the question into a TokenReview, the status back into gated's
// terms. What the answer means is decided by serviceaccount.Judge, which never
// sees a Kubernetes type.
//
// The permission it needs is not in the generated role. Creating a
// TokenReview is what system:auth-delegator grants, and the manifests bind
// gated's ServiceAccount to that ClusterRole rather than repeating it here.
type TokenReviewer struct {
	// Client creates the review. A TokenReview is never stored, so it is
	// sent to the API server directly and never read from a cache.
	Client client.Client
}

// Review asks whether token is good for audience.
func (r *TokenReviewer) Review(ctx context.Context, token, audience string) (serviceaccount.Review, error) {
	review := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token:     token,
			Audiences: []string{audience},
		},
	}
	if err := r.Client.Create(ctx, review); err != nil {
		return serviceaccount.Review{}, fmt.Errorf("creating a TokenReview: %w", err)
	}
	return serviceaccount.Review{
		Authenticated: review.Status.Authenticated,
		Username:      review.Status.User.Username,
		Audiences:     review.Status.Audiences,
		Error:         review.Status.Error,
	}, nil
}
