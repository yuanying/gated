package connector

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func newGitHubUnderTest(t *testing.T, fake *fakeGitHub) *GitHub {
	t.Helper()
	return &GitHub{
		ClientID:     fake.clientID,
		ClientSecret: StaticSecret(fake.clientSecret),
		BaseURL:      fake.URL,
		APIURL:       fake.URL,
		HTTPClient:   fake.Client(),
	}
}

// TestGitHubAuthorizeURLCarriesNoSecret is the one property of the URL that
// matters: it is handed to the browser, so anything in it is public.
func TestGitHubAuthorizeURLCarriesNoSecret(t *testing.T) {
	fake := newFakeGitHub(t)
	gh := newGitHubUnderTest(t, fake)

	raw, err := gh.AuthCodeURL(context.Background(), Request{
		RedirectURI: "https://auth.example.com/__gated/idp/github/callback",
		State:       "the-state",
		Nonce:       "the-nonce",
	})
	if err != nil {
		t.Fatalf("AuthCodeURL() = %v", err)
	}
	if strings.Contains(raw, fake.clientSecret) {
		t.Fatal("the authorize URL carries the client secret")
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %q: %v", raw, err)
	}
	if got, want := u.Query().Get("client_id"), fake.clientID; got != want {
		t.Errorf("client_id = %q, want %q", got, want)
	}
	if got, want := u.Query().Get("state"), "the-state"; got != want {
		t.Errorf("state = %q, want %q", got, want)
	}
	if got, want := u.Query().Get("redirect_uri"), "https://auth.example.com/__gated/idp/github/callback"; got != want {
		t.Errorf("redirect_uri = %q, want %q", got, want)
	}
	if !strings.HasPrefix(raw, fake.URL+"/login/oauth/authorize") {
		t.Errorf("AuthCodeURL() = %q, want it to start at the configured base", raw)
	}
}

// TestGitHubIdentifiesByLoginName covers the happy path. GitHub is not an OIDC
// provider for user login, so the identity comes from /user rather than from a
// token (ADR 0003).
func TestGitHubIdentifiesByLoginName(t *testing.T) {
	fake := newFakeGitHub(t)
	gh := newGitHubUnderTest(t, fake)

	id, err := gh.Identify(context.Background(), fake.code, Request{RedirectURI: "https://auth.example.com/cb"})
	if err != nil {
		t.Fatalf("Identify() = %v", err)
	}
	if want := "github:octocat"; id.Subject != want {
		t.Errorf("Subject = %q, want %q", id.Subject, want)
	}
	if fake.lastAuthUser != "Bearer "+fake.accessToken {
		t.Errorf("/user was called with %q, want the access token", fake.lastAuthUser)
	}
}

func TestGitHubRefusesEverythingElse(t *testing.T) {
	tests := map[string]func(*fakeGitHub){
		"the code was rejected": func(f *fakeGitHub) {
			f.code = "another-code"
		},
		"the exchange failed": func(f *fakeGitHub) {
			f.tokenStatus = 500
			f.tokenBody = "no"
		},
		"the exchange answered with an error in a 200": func(f *fakeGitHub) {
			f.tokenBody = `{"error":"bad_verification_code","error_description":"expired"}`
		},
		"the exchange answered with no token": func(f *fakeGitHub) {
			f.tokenBody = `{"token_type":"bearer"}`
		},
		"the exchange answered with something that is not JSON": func(f *fakeGitHub) {
			f.tokenBody = "access_token=gho_token&token_type=bearer"
		},
		"the token was refused by the API": func(f *fakeGitHub) {
			f.userStatus = 401
			f.userBody = `{"message":"Bad credentials"}`
		},
		"the API answered with no login": func(f *fakeGitHub) {
			f.userBody = `{"id":1}`
		},
		"the API answered with something that is not JSON": func(f *fakeGitHub) {
			f.userBody = "octocat"
		},
	}

	for name, break_ := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakeGitHub(t)
			gh := newGitHubUnderTest(t, fake)
			break_(fake)

			id, err := gh.Identify(context.Background(), "the-code", Request{RedirectURI: "https://auth.example.com/cb"})
			if err == nil {
				t.Fatalf("Identify() = %q, nil; want an error", id.Subject)
			}
			if id.Subject != "" {
				t.Errorf("Identify() returned the subject %q alongside an error", id.Subject)
			}
		})
	}
}

// TestGitHubNeedsItsClientSecret checks that a connector whose secret has not
// been read yet refuses rather than exchanging with an empty one.
func TestGitHubNeedsItsClientSecret(t *testing.T) {
	fake := newFakeGitHub(t)
	gh := newGitHubUnderTest(t, fake)
	gh.ClientSecret = failingSecret{}

	if _, err := gh.Identify(context.Background(), fake.code, Request{RedirectURI: "https://auth.example.com/cb"}); err == nil {
		t.Fatal("Identify() = nil; want an error when the client secret cannot be read")
	}
}

func TestGitHubIsNamedForItsSubjectPrefix(t *testing.T) {
	gh := &GitHub{}
	if gh.Name() != "github" {
		t.Errorf("Name() = %q, want %q", gh.Name(), "github")
	}
}

type failingSecret struct{}

func (failingSecret) Secret(context.Context) (string, error) {
	return "", errNoSecret
}
