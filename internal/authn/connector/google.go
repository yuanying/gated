package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// GoogleName is how this provider is spelled in a URL and in a state token.
const GoogleName = "google"

// DefaultGoogleIssuer is the OpenID Connect issuer of Google accounts. It is a
// field on the connector so that the mock provider the end-to-end tests run
// against can be pointed at instead (ADR 0007).
const DefaultGoogleIssuer = "https://accounts.google.com"

// googleSubjectPrefix is what a verified address becomes (ADR 0002).
//
// It is written here and used in exactly one function, googleSubject, which
// can only be handed a verifiedAddress. That is what makes it impossible to
// build a Google subject without having read email_verified.
const googleSubjectPrefix = "google:"

// mailAddress is the shape a subject's address has to have. It matches the
// pattern the CRD schema enforces on a NetworkRoleBinding, so that an identity
// gated establishes can be spelled in a binding.
var mailAddress = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// Google identifies a visitor by the mail address on their account.
//
// Unlike GitHub, Google is an OpenID Connect provider, so the identity comes
// out of a signed ID token rather than out of an API call. The address is only
// an identity once the provider says it has verified it (ADR 0003).
type Google struct {
	// ClientID is the OAuth client. Required.
	ClientID string
	// ClientSecret hands out the client's secret. Required.
	ClientSecret SecretSource

	// Issuer is the OpenID Connect issuer. Empty means Google's own.
	Issuer string
	// HTTPClient talks to the provider. Empty means a client with a timeout.
	HTTPClient *http.Client
	// Now reads the clock the ID token's validity is judged against.
	Now func() time.Time

	once sync.Once
	oidc *oidcClient
}

// Name returns the provider's name.
func (g *Google) Name() string { return GoogleName }

// AuthCodeURL is where the browser goes to log in.
func (g *Google) AuthCodeURL(ctx context.Context, req Request) (string, error) {
	if g.ClientID == "" {
		return "", errors.New("the Google OAuth client has no client ID")
	}
	cfg, err := g.client().discover(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{
		"client_id":     {g.ClientID},
		"redirect_uri":  {req.RedirectURI},
		"response_type": {"code"},
		// openid for the ID token, email for the address that is the
		// identity. Nothing else is asked for, because nothing else is
		// used.
		"scope": {"openid email"},
		"state": {req.State},
	}
	if req.Nonce != "" {
		q.Set("nonce", req.Nonce)
	}
	separator := "?"
	if strings.Contains(cfg.AuthorizationEndpoint, "?") {
		separator = "&"
	}
	return cfg.AuthorizationEndpoint + separator + q.Encode(), nil
}

// Identify completes the exchange and reads the identity out of the ID token.
func (g *Google) Identify(ctx context.Context, code string, req Request) (Identity, error) {
	secret, err := clientSecret(ctx, g.ClientSecret)
	if err != nil {
		return Identity{}, err
	}
	client := g.client()
	cfg, err := client.discover(ctx)
	if err != nil {
		return Identity{}, err
	}
	raw, err := client.exchange(ctx, cfg, g.ClientID, secret, code, req.RedirectURI)
	if err != nil {
		return Identity{}, err
	}
	claims, err := client.verifyIDToken(ctx, raw, g.ClientID, req.Nonce)
	if err != nil {
		return Identity{}, err
	}

	address, err := requireVerifiedEmail(claims)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Subject: googleSubject(address)}, nil
}

func (g *Google) client() *oidcClient {
	g.once.Do(func() {
		issuer := g.Issuer
		if issuer == "" {
			issuer = DefaultGoogleIssuer
		}
		g.oidc = newOIDCClient(issuer, g.HTTPClient, g.Now)
	})
	return g.oidc
}

// verifiedAddress is a mail address an ID token said the provider had
// verified.
//
// It is a type of its own, and unexported, so that the only way to obtain one
// is to call requireVerifiedEmail. googleSubject takes nothing else, so the
// compiler makes the check ADR 0003 asks for unavoidable rather than
// remembered.
type verifiedAddress string

// requireVerifiedEmail reads the address out of an ID token, refusing one the
// provider has not verified.
//
// This is the check ADR 0003 names on its own. The address is the identifier a
// NetworkRoleBinding grants to, so believing an unverified one hands whatever
// that binding granted to whoever typed the address into their profile.
func requireVerifiedEmail(claims *idClaims) (verifiedAddress, error) {
	if claims == nil {
		return "", errors.New("the ID token carried no claims")
	}
	address := strings.TrimSpace(claims.Email)
	if address == "" {
		return "", errors.New("the ID token carries no mail address, so there is no identity in it")
	}
	if !claims.EmailVerified {
		return "", fmt.Errorf("the provider has not verified the address %q, so it says nothing about who this is", address)
	}
	address = strings.ToLower(address)
	if !mailAddress.MatchString(address) {
		return "", fmt.Errorf("%q is not a mail address", address)
	}
	return verifiedAddress(address), nil
}

// googleSubject spells a verified address as a subject (ADR 0002).
func googleSubject(address verifiedAddress) string {
	return googleSubjectPrefix + string(address)
}
