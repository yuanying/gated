// Package connector talks to the identity providers gated accepts.
//
// Each provider is implemented on its own rather than behind one generic OIDC
// relying party (ADR 0003): GitHub offers no OIDC for user login, so its
// identity comes from an OAuth exchange followed by a call to /user, while
// Google's comes from an ID token. Adding a provider means adding a Connector,
// and nothing outside this package learns which one answered.
package connector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"
)

// defaultTimeout bounds every request to a provider. A login that hangs is a
// visitor watching a blank page, and the request it belongs to is holding a
// connection open on the way in.
const defaultTimeout = 15 * time.Second

// maxResponseSize bounds what is read back from a provider.
const maxResponseSize = 1 << 20

// Identity is what a completed login established.
//
// It is the subject and nothing else. What that subject may do is decided per
// request against NetworkRole and NetworkRoleBinding, never here (ADR 0003).
type Identity struct {
	// Subject is the principal, in the vocabulary of ADR 0002:
	// github:<login> or google:<mail address>.
	Subject string
}

// Request is what one login round trip needs to agree on.
//
// The same values are used to build the authorize URL and to complete the
// exchange, because the provider checks that they match.
type Request struct {
	// RedirectURI is where the provider sends the browser back to. It is
	// registered with the provider, so it is the same for every host gated
	// protects (ADR 0003).
	RedirectURI string
	// State is the opaque value that comes back with the code.
	State string
	// Nonce ties an ID token to this login. Providers that do not issue ID
	// tokens ignore it.
	Nonce string
}

// Connector is one identity provider.
type Connector interface {
	// Name is how the provider is spelled in a URL and in a state token.
	Name() string
	// AuthCodeURL is where the visitor's browser is sent to log in. It is
	// handed to the browser, so it carries no client secret.
	AuthCodeURL(ctx context.Context, req Request) (string, error)
	// Identify completes the exchange and says who the visitor is. It
	// returns an error and no subject when anything at all is wrong: a
	// login that cannot be completed is not an anonymous one.
	Identify(ctx context.Context, code string, req Request) (Identity, error)
}

// SecretSource hands out a client secret.
//
// It is an interface because the secret lives in a Kubernetes Secret that may
// be rotated, or may not have been read yet when the process starts
// (ADR 0009). Nothing in this package knows that.
type SecretSource interface {
	Secret(ctx context.Context) (string, error)
}

// StaticSecret is a secret held in memory, for tests and for callers that read
// it once themselves.
type StaticSecret string

// Secret returns the held value.
func (s StaticSecret) Secret(context.Context) (string, error) { return string(s), nil }

// errNoSecret is what a connector reports when its client secret is not
// available. Exchanging with an empty secret would be reported by the provider
// as a client error, which reads like a misconfigured application rather than
// a Secret that has not arrived.
var errNoSecret = errors.New("the OAuth client secret is not available")

// clientSecret reads a secret, refusing an empty one.
func clientSecret(ctx context.Context, src SecretSource) (string, error) {
	if src == nil {
		return "", errNoSecret
	}
	secret, err := src.Secret(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errNoSecret, err)
	}
	if secret == "" {
		return "", errNoSecret
	}
	return secret, nil
}

// Set is the providers one installation accepts, in a stable order.
type Set struct {
	byName map[string]Connector
	names  []string
}

// NewSet collects connectors, ignoring nils so that a caller can build the set
// from optional configuration without counting first.
func NewSet(connectors ...Connector) *Set {
	s := &Set{byName: map[string]Connector{}}
	for _, c := range connectors {
		if c == nil || c.Name() == "" {
			continue
		}
		if _, dup := s.byName[c.Name()]; dup {
			continue
		}
		s.byName[c.Name()] = c
		s.names = append(s.names, c.Name())
	}
	sort.Strings(s.names)
	return s
}

// Lookup returns the connector with this name.
func (s *Set) Lookup(name string) (Connector, bool) {
	if s == nil {
		return nil, false
	}
	c, ok := s.byName[name]
	return c, ok
}

// Names lists the configured providers, sorted, so that a page offering a
// choice between them is the same on every replica.
func (s *Set) Names() []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s.names))
	copy(out, s.names)
	return out
}

// Len is how many providers are configured.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.names)
}

// Only returns the single configured provider, if there is exactly one. A
// visitor is not asked to choose between one thing.
func (s *Set) Only() (Connector, bool) {
	if s.Len() != 1 {
		return nil, false
	}
	return s.byName[s.names[0]], true
}

// httpClient returns the client to use, defaulting to one with a timeout.
func httpClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: defaultTimeout}
}

// readBody reads a bounded response body.
func readBody(r *http.Response) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, maxResponseSize))
}

// SecretFunc adapts a function to a SecretSource.
type SecretFunc func(ctx context.Context) (string, error)

// Secret calls the function.
func (f SecretFunc) Secret(ctx context.Context) (string, error) { return f(ctx) }
