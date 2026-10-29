package serviceaccount

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

const audience = "https://auth.example.com"

// jwt builds something in the shape the API server issues. The signature is
// not one: nothing in gated checks it, the API server does (ADR 0039).
func jwt(t *testing.T, claims map[string]any) string {
	t.Helper()
	segment := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("encoding %v: %v", v, err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return segment(map[string]string{"alg": "RS256", "kid": "k"}) + "." + segment(claims) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("not-a-signature"))
}

func TestBearerTakesOnlyWhatLooksLikeAServiceAccountToken(t *testing.T) {
	token := jwt(t, map[string]any{"aud": []string{audience}})

	tests := []struct {
		name   string
		header string
		want   string
		ok     bool
	}{
		{name: "a bearer JWT", header: "Bearer " + token, want: token, ok: true},
		{name: "the scheme in any case", header: "bearer " + token, want: token, ok: true},
		{name: "nothing at all", header: ""},
		{
			// An AccessToken is the other door. The two are told
			// apart by the prefix, so neither ever reads the other's.
			name:   "an access token",
			header: "Bearer gat_" + token,
		},
		{name: "an opaque bearer token", header: "Bearer some-opaque-value"},
		{name: "two segments", header: "Bearer eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJ4In0"},
		{name: "four segments", header: "Bearer " + token + ".more"},
		{name: "an empty segment", header: "Bearer eyJhbGciOiJSUzI1NiJ9..c2ln"},
		{name: "segments that are not base64url", header: "Bearer a+b.c/d.e=f"},
		{name: "segments that are not JSON", header: "Bearer YWJj.ZGVm.Z2hp"},
		{
			// BASIC is how an AccessToken reaches clients that speak
			// nothing else. A service account token comes as a
			// bearer credential or not at all.
			name:   "BASIC",
			header: "Basic " + base64.StdEncoding.EncodeToString([]byte("user:"+token)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Bearer(tt.header)
			if ok != tt.ok || got != tt.want {
				t.Errorf("Bearer(%q) = %q, %v; want %q, %v", tt.header, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestJudgeBelievesOnlyAServiceAccountForThisAudience(t *testing.T) {
	tests := []struct {
		name        string
		review      Review
		wantSubject string
		wantReason  Reason
	}{
		{
			name: "authenticated for this audience",
			review: Review{
				Authenticated: true,
				Username:      "system:serviceaccount:natsumi:assistant",
				Audiences:     []string{audience},
			},
			wantSubject: "system:serviceaccount:natsumi:assistant",
			wantReason:  Accepted,
		},
		{
			name: "authenticated for this audience among others",
			review: Review{
				Authenticated: true,
				Username:      "system:serviceaccount:natsumi:assistant",
				Audiences:     []string{"a2a", audience},
			},
			wantSubject: "system:serviceaccount:natsumi:assistant",
			wantReason:  Accepted,
		},
		{
			name:       "not authenticated",
			review:     Review{Authenticated: false, Error: "invalid bearer token"},
			wantReason: Rejected,
		},
		{
			// An API server that does not support audiences
			// answers without them. Believing it would accept a
			// token minted for anybody.
			name: "authenticated without saying for whom",
			review: Review{
				Authenticated: true,
				Username:      "system:serviceaccount:natsumi:assistant",
			},
			wantReason: WrongAudience,
		},
		{
			name: "authenticated for somebody else",
			review: Review{
				Authenticated: true,
				Username:      "system:serviceaccount:natsumi:assistant",
				Audiences:     []string{"a2a"},
			},
			wantReason: WrongAudience,
		},
		{
			// The API server authenticates people too, through
			// whatever authenticators it is configured with. gated
			// takes service accounts from it and nobody else.
			name: "a user who is not a service account",
			review: Review{
				Authenticated: true,
				Username:      "kubernetes-admin",
				Audiences:     []string{audience},
			},
			wantReason: NotServiceAccount,
		},
		{
			name: "a service account with no name",
			review: Review{
				Authenticated: true,
				Username:      "system:serviceaccount:natsumi:",
				Audiences:     []string{audience},
			},
			wantReason: NotServiceAccount,
		},
		{
			name: "a service account with no namespace",
			review: Review{
				Authenticated: true,
				Username:      "system:serviceaccount::assistant",
				Audiences:     []string{audience},
			},
			wantReason: NotServiceAccount,
		},
		{
			name: "a service account name with a colon in it",
			review: Review{
				Authenticated: true,
				Username:      "system:serviceaccount:natsumi:a:b",
				Audiences:     []string{audience},
			},
			wantReason: NotServiceAccount,
		},
		{
			name: "a namespace that cannot be one",
			review: Review{
				Authenticated: true,
				Username:      "system:serviceaccount:Natsumi:assistant",
				Audiences:     []string{audience},
			},
			wantReason: NotServiceAccount,
		},
		{
			// The namespace-wide group is not a subject gated has
			// (ADR 0002 adds groups when they are needed).
			name: "the group of a namespace",
			review: Review{
				Authenticated: true,
				Username:      "system:serviceaccounts:natsumi",
				Audiences:     []string{audience},
			},
			wantReason: NotServiceAccount,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject, reason := Judge(tt.review, audience)
			if subject != tt.wantSubject || reason != tt.wantReason {
				t.Errorf("Judge() = %q, %q; want %q, %q", subject, reason, tt.wantSubject, tt.wantReason)
			}
		})
	}
}

func TestPrecheckRefusesWithoutAskingWhatCannotBeAccepted(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	later := now.Add(10 * time.Minute).Unix()

	tests := []struct {
		name       string
		claims     map[string]any
		wantReason Reason
		wantExpiry time.Time
	}{
		{
			name:       "for this audience and in date",
			claims:     map[string]any{"aud": []string{audience}, "exp": later},
			wantExpiry: time.Unix(later, 0),
		},
		{
			name:       "the audience as a single string",
			claims:     map[string]any{"aud": audience, "exp": later},
			wantExpiry: time.Unix(later, 0),
		},
		{
			// A token that says nothing about when it ends is the
			// API server's to judge, and is not cut short here.
			name:   "no expiry",
			claims: map[string]any{"aud": []string{audience}},
		},
		{
			// The token fraction-agents is called with, passing
			// through gated on its way there. Asking the API server
			// about it on every request would answer nothing new.
			name:       "for another audience",
			claims:     map[string]any{"aud": []string{"a2a"}, "exp": later},
			wantReason: WrongAudience,
		},
		{
			name:       "for no audience",
			claims:     map[string]any{"exp": later},
			wantReason: WrongAudience,
		},
		{
			name:       "expired",
			claims:     map[string]any{"aud": []string{audience}, "exp": now.Unix()},
			wantReason: Expired,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expiry, reason := precheck(jwt(t, tt.claims), audience, now)
			if reason != tt.wantReason || !expiry.Equal(tt.wantExpiry) {
				t.Errorf("precheck() = %v, %q; want %v, %q", expiry, reason, tt.wantExpiry, tt.wantReason)
			}
		})
	}
}
