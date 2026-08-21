package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// GitHubName is how this provider is spelled in a URL and in a state token.
const GitHubName = "github"

// The endpoints of github.com. They are fields on the connector rather than
// constants so that GitHub Enterprise, and the mock provider the end-to-end
// tests run against, can be pointed at instead (ADR 0007).
const (
	// DefaultGitHubBaseURL is where the OAuth endpoints live.
	DefaultGitHubBaseURL = "https://github.com"
	// DefaultGitHubAPIURL is the root of the REST API.
	DefaultGitHubAPIURL = "https://api.github.com"
)

// githubSubjectPrefix is what a GitHub login becomes (ADR 0002).
const githubSubjectPrefix = "github:"

// githubLogin is what GitHub allows an account to be called. Checking it here
// keeps a subject from ever containing the separator that gives it its
// meaning, whatever an API on the other side of the network answered with.
var githubLogin = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)

// GitHub identifies a visitor by their account name.
//
// GitHub publishes no OIDC provider for user login, so this is an OAuth 2.0
// exchange followed by a call to /user (ADR 0003). The account name is used
// rather than an address: an address can be unverified, one of several, or
// changed quietly, while the login is what the account is.
type GitHub struct {
	// ClientID is the OAuth application. Required.
	ClientID string
	// ClientSecret hands out the application's secret. Required.
	ClientSecret SecretSource

	// BaseURL is where /login/oauth/* live. Empty means github.com.
	BaseURL string
	// APIURL is the root of the REST API. Empty means api.github.com.
	APIURL string
	// HTTPClient talks to GitHub. Empty means a client with a timeout.
	HTTPClient *http.Client
}

// Name returns the provider's name.
func (g *GitHub) Name() string { return GitHubName }

// AuthCodeURL is where the browser goes to log in.
//
// No scope is requested. /user answers with the login for a token with no
// scope at all, so asking for one would be asking the visitor to grant access
// gated does not use.
func (g *GitHub) AuthCodeURL(_ context.Context, req Request) (string, error) {
	if g.ClientID == "" {
		return "", errors.New("the GitHub OAuth application has no client ID")
	}
	q := url.Values{
		"client_id":    {g.ClientID},
		"redirect_uri": {req.RedirectURI},
		"state":        {req.State},
	}
	return g.baseURL() + "/login/oauth/authorize?" + q.Encode(), nil
}

// Identify trades the code for a token and asks GitHub whose it is.
func (g *GitHub) Identify(ctx context.Context, code string, req Request) (Identity, error) {
	token, err := g.exchange(ctx, code, req.RedirectURI)
	if err != nil {
		return Identity{}, err
	}
	login, err := g.login(ctx, token)
	if err != nil {
		return Identity{}, err
	}
	if !githubLogin.MatchString(login) {
		return Identity{}, fmt.Errorf("GitHub answered with %q, which is not an account name", login)
	}
	return Identity{Subject: githubSubjectPrefix + login}, nil
}

// exchange trades the authorisation code for an access token.
func (g *GitHub) exchange(ctx context.Context, code, redirectURI string) (string, error) {
	secret, err := clientSecret(ctx, g.ClientSecret)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"client_id":     {g.ClientID},
		"client_secret": {secret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		g.baseURL()+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Without this GitHub answers in form encoding.
	request.Header.Set("Accept", "application/json")

	response, err := httpClient(g.HTTPClient).Do(request)
	if err != nil {
		return "", fmt.Errorf("exchanging the code with GitHub: %w", err)
	}
	defer response.Body.Close()
	body, err := readBody(response)
	if err != nil {
		return "", fmt.Errorf("reading GitHub's answer: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub answered the exchange with %s", response.Status)
	}

	var out struct {
		AccessToken      string `json:"access_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("GitHub answered the exchange with something that is not JSON: %w", err)
	}
	// A rejected code comes back as 200 with an error in the body, so the
	// status on its own is not the answer.
	if out.Error != "" {
		return "", fmt.Errorf("GitHub refused the exchange: %s (%s)", out.Error, out.ErrorDescription)
	}
	if out.AccessToken == "" {
		return "", errors.New("GitHub answered the exchange with no token")
	}
	return out.AccessToken, nil
}

// login asks GitHub which account the token belongs to.
func (g *GitHub) login(ctx context.Context, token string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, g.apiURL()+"/user", nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")

	response, err := httpClient(g.HTTPClient).Do(request)
	if err != nil {
		return "", fmt.Errorf("asking GitHub who this is: %w", err)
	}
	defer response.Body.Close()
	body, err := readBody(response)
	if err != nil {
		return "", fmt.Errorf("reading GitHub's answer: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub answered /user with %s", response.Status)
	}

	var out struct {
		Login string `json:"login"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("GitHub answered /user with something that is not JSON: %w", err)
	}
	if out.Login == "" {
		return "", errors.New("GitHub answered /user with no account name")
	}
	return out.Login, nil
}

func (g *GitHub) baseURL() string {
	if g.BaseURL == "" {
		return DefaultGitHubBaseURL
	}
	return strings.TrimSuffix(g.BaseURL, "/")
}

func (g *GitHub) apiURL() string {
	if g.APIURL == "" {
		return DefaultGitHubAPIURL
	}
	return strings.TrimSuffix(g.APIURL, "/")
}
