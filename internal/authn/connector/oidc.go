package connector

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The OpenID Connect half of this package: discovery, the key set, and the
// verification of one ID token.
//
// Only RS256 is accepted. An ID token names its own algorithm, so a verifier
// that honours that name can be handed "none", or handed a symmetric algorithm
// keyed with the public modulus everybody can read. Pinning the algorithm to
// the one the provider actually uses removes both.

const (
	// signingAlgorithm is the only algorithm an ID token may be signed with.
	signingAlgorithm = "RS256"
	// jwksMinRefresh is how often the key set may be re-fetched when a token
	// names a key that is not in it. Without a floor, a stream of tokens
	// naming keys that do not exist becomes a stream of requests to the
	// provider.
	jwksMinRefresh = time.Minute
	// issuedAtLeeway allows for the clocks of gated and the provider
	// disagreeing slightly. The expiry gets no such allowance: an ID token
	// is verified within seconds of being issued, so there is no reason to
	// keep honouring one after the provider says it is done.
	issuedAtLeeway = 2 * time.Minute
)

// oidcConfig is the part of the discovery document gated uses.
type oidcConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// oidcClient is one OpenID Connect provider.
type oidcClient struct {
	issuer string
	client *http.Client
	now    func() time.Time

	mu        sync.Mutex
	config    *oidcConfig
	keys      map[string]*rsa.PublicKey
	keysAt    time.Time
	keysValid bool
}

func newOIDCClient(issuer string, client *http.Client, now func() time.Time) *oidcClient {
	if now == nil {
		now = time.Now
	}
	return &oidcClient{issuer: strings.TrimSuffix(issuer, "/"), client: httpClient(client), now: now}
}

// discover reads the provider's configuration, once.
//
// The document has to agree with the URL it was fetched from. A document that
// names another issuer is either a misconfiguration or a provider being
// impersonated, and in both cases the endpoints in it should not be used.
func (c *oidcClient) discover(ctx context.Context) (*oidcConfig, error) {
	c.mu.Lock()
	cached := c.config
	c.mu.Unlock()
	if cached != nil {
		return cached, nil
	}

	var cfg oidcConfig
	if err := c.getJSON(ctx, c.issuer+"/.well-known/openid-configuration", &cfg); err != nil {
		return nil, fmt.Errorf("reading the OpenID configuration of %s: %w", c.issuer, err)
	}
	if strings.TrimSuffix(cfg.Issuer, "/") != c.issuer {
		return nil, fmt.Errorf("the OpenID configuration at %s says its issuer is %q", c.issuer, cfg.Issuer)
	}
	if cfg.AuthorizationEndpoint == "" || cfg.TokenEndpoint == "" || cfg.JWKSURI == "" {
		return nil, fmt.Errorf("the OpenID configuration of %s is missing an endpoint", c.issuer)
	}

	c.mu.Lock()
	c.config = &cfg
	c.mu.Unlock()
	return &cfg, nil
}

// exchange trades an authorisation code for an ID token.
func (c *oidcClient) exchange(ctx context.Context, cfg *oidcConfig, clientID, secret, code, redirectURI string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {secret},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")

	response, err := c.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("exchanging the code with %s: %w", c.issuer, err)
	}
	defer response.Body.Close()
	body, err := readBody(response)
	if err != nil {
		return "", fmt.Errorf("reading the answer from %s: %w", c.issuer, err)
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s answered the exchange with %s", c.issuer, response.Status)
	}

	var out struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("%s answered the exchange with something that is not JSON: %w", c.issuer, err)
	}
	if out.Error != "" {
		return "", fmt.Errorf("%s refused the exchange: %s", c.issuer, out.Error)
	}
	if strings.TrimSpace(out.IDToken) == "" {
		return "", fmt.Errorf("%s answered the exchange with no ID token", c.issuer)
	}
	return out.IDToken, nil
}

// idClaims is what an ID token says.
//
// EmailVerified is a bool, deliberately. A provider that answers with the
// string "true" fails to decode here rather than being read as verified, which
// is the direction ADR 0003 asks for.
type idClaims struct {
	Issuer        string   `json:"iss"`
	Audience      audience `json:"aud"`
	Subject       string   `json:"sub"`
	Nonce         string   `json:"nonce"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	IssuedAt      int64    `json:"iat"`
	Expires       int64    `json:"exp"`
}

// audience is the aud claim, which is one string or several.
type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return errors.New("the aud claim is neither a string nor a list of strings")
	}
	*a = audience(many)
	return nil
}

func (a audience) contains(want string) bool {
	for _, got := range a {
		if got == want {
			return true
		}
	}
	return false
}

// verifyIDToken checks a token's signature and every claim that decides
// whether it is about this login, and returns what it said.
func (c *oidcClient) verifyIDToken(ctx context.Context, raw, clientID, nonce string) (*idClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("the ID token is not a JWT")
	}

	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, fmt.Errorf("the ID token's header cannot be read: %w", err)
	}
	if header.Algorithm != signingAlgorithm {
		return nil, fmt.Errorf("the ID token is signed with %q; only %s is accepted", header.Algorithm, signingAlgorithm)
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("the ID token's signature cannot be read")
	}
	key, err := c.publicKey(ctx, header.KeyID)
	if err != nil {
		return nil, err
	}
	digest := crypto.SHA256.New()
	digest.Write([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest.Sum(nil), signature); err != nil {
		return nil, errors.New("the ID token is not signed by the provider it claims to come from")
	}

	var claims idClaims
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, fmt.Errorf("the ID token's claims cannot be read: %w", err)
	}
	if !c.issuedByUs(claims.Issuer) {
		return nil, fmt.Errorf("the ID token was issued by %q, not by %s", claims.Issuer, c.issuer)
	}
	if !claims.Audience.contains(clientID) {
		return nil, errors.New("the ID token was issued for another application")
	}
	now := c.now()
	if claims.Expires == 0 || !now.Before(time.Unix(claims.Expires, 0)) {
		return nil, errors.New("the ID token has expired")
	}
	if claims.IssuedAt != 0 && time.Unix(claims.IssuedAt, 0).After(now.Add(issuedAtLeeway)) {
		return nil, errors.New("the ID token was issued in the future")
	}
	if nonce != "" && claims.Nonce != nonce {
		return nil, errors.New("the ID token belongs to another login")
	}
	return &claims, nil
}

// issuedByUs compares the iss claim with the configured issuer.
//
// The scheme is optional on the token's side: providers exist that publish
// their issuer as a URL and stamp their tokens with the bare hostname.
func (c *oidcClient) issuedByUs(iss string) bool {
	got := strings.TrimSuffix(iss, "/")
	if got == c.issuer {
		return true
	}
	return got != "" && got == strings.TrimPrefix(c.issuer, "https://")
}

// publicKey returns the key an ID token names, fetching the set if it is not
// held or if the named key is not in the set held.
func (c *oidcClient) publicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if key, ok := c.cachedKey(kid); ok {
		return key, nil
	}
	if err := c.fetchKeys(ctx); err != nil {
		return nil, err
	}
	if key, ok := c.cachedKey(kid); ok {
		return key, nil
	}
	return nil, fmt.Errorf("the ID token names a key %q that %s does not publish", kid, c.issuer)
}

func (c *oidcClient) cachedKey(kid string) (*rsa.PublicKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.keysValid {
		return nil, false
	}
	// A provider that publishes exactly one key may leave the kid out of
	// both the set and the token.
	if kid == "" && len(c.keys) == 1 {
		for _, key := range c.keys {
			return key, true
		}
	}
	key, ok := c.keys[kid]
	return key, ok
}

func (c *oidcClient) fetchKeys(ctx context.Context) error {
	c.mu.Lock()
	if c.keysValid && c.now().Sub(c.keysAt) < jwksMinRefresh {
		c.mu.Unlock()
		return fmt.Errorf("the key set of %s was read recently and does not hold this key", c.issuer)
	}
	c.mu.Unlock()

	cfg, err := c.discover(ctx)
	if err != nil {
		return err
	}

	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := c.getJSON(ctx, cfg.JWKSURI, &set); err != nil {
		return fmt.Errorf("reading the key set of %s: %w", c.issuer, err)
	}

	keys := map[string]*rsa.PublicKey{}
	for _, jwk := range set.Keys {
		if jwk.Kty != "RSA" || (jwk.Use != "" && jwk.Use != "sig") {
			continue
		}
		if jwk.Alg != "" && jwk.Alg != signingAlgorithm {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			continue
		}
		e, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil || len(e) == 0 || len(e) > 8 {
			continue
		}
		keys[jwk.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if len(keys) == 0 {
		return fmt.Errorf("%s publishes no usable signing key", c.issuer)
	}

	c.mu.Lock()
	c.keys, c.keysAt, c.keysValid = keys, c.now(), true
	c.mu.Unlock()
	return nil
}

func (c *oidcClient) getJSON(ctx context.Context, endpoint string, out any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")

	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := readBody(response)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered with %s", endpoint, response.Status)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%s answered with something that is not JSON: %w", endpoint, err)
	}
	return nil
}

func decodeSegment(segment string, out any) error {
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return errors.New("it is not base64url")
	}
	return json.Unmarshal(decoded, out)
}
