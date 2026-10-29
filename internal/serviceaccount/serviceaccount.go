// Package serviceaccount establishes which Kubernetes ServiceAccount is behind
// a request that carries one of its tokens (ADR 0039).
//
// gated does not verify the token itself. The API server issued it and is the
// one that can say whether it still stands — whether it was signed by the
// cluster, whether its Pod or ServiceAccount still exists, whether it was
// meant for gated — so every token gated has not seen recently is put to a
// TokenReview. What comes back is judged here, by a pure function over the
// answer, and the Kubernetes types stay on the far side of Reviewer (ADR 0007).
//
// A token is believed only when the API server says it was issued for gated's
// own audience. A token minted for something else — the one fraction-agents is
// called with, say — is not gated's, and goes on to the backend untouched.
package serviceaccount

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"time"

	k8svalidation "k8s.io/apimachinery/pkg/util/validation"

	gatev1alpha1 "github.com/yuanying/gated/internal/apis/gate/v1alpha1"
)

// SubjectPrefix is what the name of every ServiceAccount starts with, in the
// spelling RBAC and the TokenReview both use. gated's subject is that name
// unchanged, so that the string in a NetworkRoleBinding is the one a
// RoleBinding would hold.
const SubjectPrefix = gatev1alpha1.SubjectPrefixServiceAccount

// maxTokenSize bounds what will be decoded at all. The API server's tokens are
// a little over a kilobyte.
const maxTokenSize = 8192

// Bearer returns the token an Authorization header carries, when it is in the
// shape the API server issues: a JWT, presented as a bearer credential.
//
// The shape is all that is looked at. It is enough to tell a ServiceAccount
// token from an AccessToken, which starts with gat_ and is never a JWT, and
// from the opaque tokens a backend might issue for itself, which are none of
// gated's business.
func Bearer(header string) (string, bool) {
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimLeft(token, " ")
	if len(token) == 0 || len(token) > maxTokenSize || strings.HasPrefix(token, gatev1alpha1.TokenPrefix) {
		return "", false
	}

	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return "", false
	}
	for _, s := range segments {
		if s == "" {
			return "", false
		}
	}
	for _, s := range segments[:2] {
		var object map[string]json.RawMessage
		if decodeSegment(s, &object) != nil {
			return "", false
		}
	}
	if _, err := base64.RawURLEncoding.DecodeString(segments[2]); err != nil {
		return "", false
	}
	return token, true
}

// Review is what the API server said about a token: the status of a
// TokenReview, in gated's own terms.
type Review struct {
	// Authenticated is whether the API server stands behind the token.
	Authenticated bool
	// Username is who the token belongs to.
	Username string
	// Audiences are the ones, of those asked about, that the token is good
	// for.
	Audiences []string
	// Error is the API server's explanation of a refusal. It names no
	// token and is safe to log.
	Error string
}

// Reviewer asks the API server about a token. It is the one place gated talks
// to anything about one, and the seam a test replaces.
type Reviewer interface {
	// Review asks whether token is good for audience. An error means no
	// answer was had, not that the answer was no.
	Review(ctx context.Context, token, audience string) (Review, error)
}

// Reason is why a token was or was not believed. It is the label the metrics
// count by and what the log says, so the set is closed and spelled once.
type Reason string

const (
	// Accepted is a token the API server stands behind, for gated's
	// audience, belonging to a ServiceAccount.
	Accepted Reason = "accepted"
	// WrongAudience is a token minted for something other than gated.
	WrongAudience Reason = "wrong_audience"
	// Expired is a token whose own expiry has passed.
	Expired Reason = "expired"
	// Rejected is a token the API server does not stand behind: forged,
	// revoked, or belonging to a Pod or ServiceAccount that is gone.
	Rejected Reason = "rejected"
	// NotServiceAccount is a token the API server authenticated as
	// somebody who is not a ServiceAccount.
	NotServiceAccount Reason = "not_serviceaccount"
	// ReviewFailed is a token nobody could answer for, because the API
	// server could not be asked.
	ReviewFailed Reason = "review_failed"
)

// Judge decides what a TokenReview means for gated.
//
// It believes the answer only when everything about it says ServiceAccount
// and gated: the API server authenticated the token, the audience it was
// asked about is among those it confirmed, and the user is a ServiceAccount
// whose namespace and name could be real. An answer that confirms no audience
// at all is not a yes. It is what an API server that does not check audiences
// says, and taking it would accept a token minted for anybody.
func Judge(review Review, audience string) (string, Reason) {
	if !review.Authenticated {
		return "", Rejected
	}
	if audience == "" || !slices.Contains(review.Audiences, audience) {
		return "", WrongAudience
	}
	if !IsSubject(review.Username) {
		return "", NotServiceAccount
	}
	return review.Username, Accepted
}

// IsSubject reports whether s names one ServiceAccount, in the form
// system:serviceaccount:<namespace>:<name>.
func IsSubject(s string) bool {
	rest, found := strings.CutPrefix(s, SubjectPrefix)
	if !found {
		return false
	}
	namespace, name, found := strings.Cut(rest, ":")
	if !found {
		return false
	}
	return len(k8svalidation.IsDNS1123Label(namespace)) == 0 &&
		len(k8svalidation.IsDNS1123Subdomain(name)) == 0
}

// claims are the parts of the token's own payload gated reads before asking.
type claims struct {
	Audience audiences `json:"aud"`
	Expiry   *int64    `json:"exp"`
}

// audiences reads the aud claim, which JWT allows to be a string or a list.
type audiences []string

func (a *audiences) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*a = audiences{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// precheck reads what the token says about itself, unverified, and refuses
// what the API server would refuse anyway: a token for another audience and
// one that has expired. It never accepts anything — a claim nobody has checked
// can only ever be a reason to say no — and what it does refuse is refused
// without a round trip to the API server, which is what keeps tokens meant for
// somebody else from costing a TokenReview on every request they pass through.
//
// The expiry it returns, for a token it does not refuse, is the token's own,
// or the zero time when it names none. A remembered answer must not outlive
// it.
func precheck(token, audience string, now time.Time) (time.Time, Reason) {
	_, rest, _ := strings.Cut(token, ".")
	payload, _, _ := strings.Cut(rest, ".")
	var c claims
	if decodeSegment(payload, &c) != nil {
		// Bearer has already decoded it once; if this one fails the
		// token is not what it looked like, and the API server will
		// say so.
		return time.Time{}, ""
	}
	if !slices.Contains(c.Audience, audience) {
		return time.Time{}, WrongAudience
	}
	if c.Expiry == nil {
		return time.Time{}, ""
	}
	expiry := time.Unix(*c.Expiry, 0)
	if !now.Before(expiry) {
		return time.Time{}, Expired
	}
	return expiry, ""
}

func decodeSegment(segment string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}
