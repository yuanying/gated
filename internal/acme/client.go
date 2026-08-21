// Package acme obtains certificates from an ACME directory.
//
// gated talks to the CA itself rather than delegating to cert-manager (ADR
// 0005). What that costs is this package: an account key, an order, a
// challenge somebody has to answer, and a certificate signing request. What it
// buys is that the challenge is answered by the same process that serves the
// traffic, with no temporary Ingress and no solver Pod in between.
//
// How a challenge is answered is behind the Solver interface. Only HTTP-01 has
// an implementation; nothing here is specific to it beyond one switch on the
// challenge type.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	xacme "golang.org/x/crypto/acme"
)

// Keypair is an issued certificate chain and its private key, in the PEM form
// a kubernetes.io/tls Secret holds.
type Keypair struct {
	// CertPEM is the leaf followed by the chain the CA sent with it.
	CertPEM []byte
	// KeyPEM is the private key, PKCS#8.
	KeyPEM []byte
}

// Client orders certificates from one ACME directory.
//
// One directory and one contact, given at startup rather than through a CRD
// (ADR 0005): gated has no reason to hold more than one issuer.
type Client struct {
	// DirectoryURL is the ACME directory to order from. Required.
	DirectoryURL string
	// Email is the contact registered with the account. Required.
	Email string
	// Accounts supplies the account key, shared between replicas.
	// Required.
	Accounts AccountStore
	// Solver answers the challenges the CA sets. Required.
	Solver Solver
	// HTTPClient talks to the directory. Nil uses the default client.
	HTTPClient *http.Client
	// UserAgent identifies gated to the CA.
	UserAgent string
	// Log records the steps of an order. The zero Logger discards.
	Log logr.Logger

	mu     sync.Mutex
	client *xacme.Client
}

// Obtain runs one order to completion and returns the issued keypair.
//
// It is a plain method with no notion of who is allowed to call it. Limiting
// issuance to the elected leader (ADR 0006) is the caller's decision, not a
// property of the client.
func (c *Client) Obtain(ctx context.Context, hosts []string) (*Keypair, error) {
	wanted := canonicalHosts(hosts)
	if len(wanted) == 0 {
		return nil, errors.New("an order needs at least one host")
	}

	client, err := c.acmeClient(ctx)
	if err != nil {
		return nil, err
	}

	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(wanted...))
	if err != nil {
		return nil, fmt.Errorf("opening an order for %s: %w", strings.Join(wanted, ", "), err)
	}
	c.Log.V(1).Info("ordering a certificate", "hosts", wanted, "order", order.URI)

	// Everything presented is taken back down, on the failing paths too: a
	// token left behind in the shared Secret is answered by every replica
	// long after the order it belonged to is gone.
	var presented []Challenge
	defer func() {
		for _, ch := range presented {
			if err := c.Solver.CleanUp(context.WithoutCancel(ctx), ch); err != nil {
				c.Log.Error(err, "removing a challenge", "host", ch.Identifier)
			}
		}
	}()

	for _, url := range order.AuthzURLs {
		if err := c.authorize(ctx, client, url, &presented); err != nil {
			return nil, err
		}
	}

	// The order URL is kept from here on. A directory is not obliged to
	// repeat it in a Location header on later responses, and Pebble does
	// not, so the value the order came back with is the only one there is.
	orderURL := order.URI
	order, err = client.WaitOrder(ctx, orderURL)
	if err != nil {
		return nil, fmt.Errorf("waiting for the order to be ready: %w", err)
	}

	key, err := newKey()
	if err != nil {
		return nil, fmt.Errorf("generating a certificate key: %w", err)
	}
	csr, err := certificateRequest(key, wanted)
	if err != nil {
		return nil, fmt.Errorf("building the certificate request: %w", err)
	}
	der, err := finalize(ctx, client, orderURL, order.FinalizeURL, csr)
	if err != nil {
		return nil, err
	}

	keypair, err := encodeKeypair(der, key)
	if err != nil {
		return nil, err
	}
	c.Log.Info("obtained a certificate", "hosts", wanted)
	return keypair, nil
}

// finalize submits the request and collects the issued chain.
//
// The straightforward call does both, but it polls the order at the URL the
// finalize response hands back in a Location header, and a directory is not
// obliged to send one. Pebble does not, which leaves that call posting to an
// empty URL. The order URL is known here — this process opened the order — so
// on that failure the order is polled directly and the certificate collected
// from it. An order that is genuinely unfinished comes back without a
// certificate, and the original failure is what is reported.
func finalize(ctx context.Context, client *xacme.Client, orderURL, finalizeURL string, csr []byte) ([][]byte, error) {
	der, _, err := client.CreateOrderCert(ctx, finalizeURL, csr, true)
	if err == nil {
		return der, nil
	}

	issued, waitErr := client.WaitOrder(ctx, orderURL)
	if waitErr != nil || issued.CertURL == "" {
		return nil, fmt.Errorf("finalizing the order: %w", err)
	}
	der, fetchErr := client.FetchCert(ctx, issued.CertURL, true)
	if fetchErr != nil {
		return nil, fmt.Errorf("collecting the issued certificate: %w", fetchErr)
	}
	return der, nil
}

// authorize takes one authorization from pending to valid, recording in
// presented whatever the solver was asked to publish.
func (c *Client) authorize(ctx context.Context, client *xacme.Client, url string, presented *[]Challenge) error {
	authz, err := client.GetAuthorization(ctx, url)
	if err != nil {
		return fmt.Errorf("reading the authorization %s: %w", url, err)
	}
	// An authorization the CA already considers valid is reused, which is
	// what keeps a second order for an overlapping set of hosts from
	// answering the same challenges again.
	if authz.Status == xacme.StatusValid {
		c.Log.V(1).Info("the authorization is already valid", "host", authz.Identifier.Value)
		return nil
	}
	if authz.Status != xacme.StatusPending {
		return fmt.Errorf("the authorization for %s is %s", authz.Identifier.Value, authz.Status)
	}

	chal, err := challengeFor(authz, c.Solver.Type())
	if err != nil {
		return fmt.Errorf("%s: %w", authz.Identifier.Value, err)
	}
	response, err := challengeResponse(client, chal.Type, chal.Token)
	if err != nil {
		return err
	}

	ch := Challenge{
		Type:       chal.Type,
		Identifier: authz.Identifier.Value,
		Wildcard:   authz.Wildcard,
		Token:      chal.Token,
		Response:   response,
	}
	// Recorded before it is presented, so that a Present that fails
	// half-way still has its leftovers taken back down.
	*presented = append(*presented, ch)
	if err := c.Solver.Present(ctx, ch); err != nil {
		return fmt.Errorf("presenting the %s challenge for %s: %w", chal.Type, ch.Identifier, err)
	}

	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accepting the %s challenge for %s: %w", chal.Type, ch.Identifier, err)
	}
	if _, err := client.WaitAuthorization(ctx, url); err != nil {
		return fmt.Errorf("validating %s: %w", ch.Identifier, err)
	}
	c.Log.V(1).Info("authorization complete", "host", ch.Identifier)
	return nil
}

// acmeClient builds the underlying client once and registers the account.
//
// Registration is idempotent: an account key the directory already knows comes
// back as ErrAccountAlreadyExists, having cached the key ID the rest of the
// exchange needs.
func (c *Client) acmeClient(ctx context.Context) (*xacme.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		return c.client, nil
	}
	if c.Accounts == nil {
		return nil, errors.New("the ACME client has no account store")
	}
	if c.Solver == nil {
		return nil, errors.New("the ACME client has no solver")
	}
	if c.DirectoryURL == "" {
		return nil, errors.New("the ACME client has no directory URL")
	}

	key, err := c.Accounts.AccountKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the ACME account key: %w", err)
	}

	client := &xacme.Client{
		Key:          key,
		DirectoryURL: c.DirectoryURL,
		HTTPClient:   c.HTTPClient,
		UserAgent:    c.UserAgent,
	}
	account := &xacme.Account{}
	if c.Email != "" {
		account.Contact = []string{"mailto:" + c.Email}
	}
	if _, err := client.Register(ctx, account, xacme.AcceptTOS); err != nil {
		if !errors.Is(err, xacme.ErrAccountAlreadyExists) {
			return nil, fmt.Errorf("registering with %s: %w", c.DirectoryURL, err)
		}
		c.Log.V(1).Info("the account key is already registered", "directory", c.DirectoryURL)
	} else {
		c.Log.Info("registered an ACME account", "directory", c.DirectoryURL)
	}

	c.client = client
	return client, nil
}

// challengeFor picks the challenge the solver can answer.
//
// The error names what the CA did offer, because the way this fails in
// practice is a solver that answers a type this directory does not hand out.
func challengeFor(authz *xacme.Authorization, want string) (*xacme.Challenge, error) {
	offered := make([]string, 0, len(authz.Challenges))
	for _, chal := range authz.Challenges {
		if chal.Type == want {
			return chal, nil
		}
		offered = append(offered, chal.Type)
	}
	return nil, fmt.Errorf("the CA offers no %s challenge, only %s", want, strings.Join(offered, ", "))
}

// challengeResponse computes what the solver has to publish.
//
// This switch is the whole of the client's knowledge of challenge types.
// Adding DNS-01 means adding a solver, not changing the order flow.
func challengeResponse(client *xacme.Client, typ, token string) (string, error) {
	switch typ {
	case ChallengeHTTP01:
		return client.HTTP01ChallengeResponse(token)
	case ChallengeDNS01:
		return client.DNS01ChallengeRecord(token)
	default:
		return "", fmt.Errorf("gated cannot compute a response for a %s challenge", typ)
	}
}

// newKey generates a key for an account or a certificate.
//
// P-256 rather than RSA: every client that matters has accepted ECDSA for
// years, and the handshake is cheaper for a process that terminates TLS for
// the whole cluster.
func newKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// certificateRequest builds the CSR for an order.
//
// The subject is left empty. A common name would repeat what the subject
// alternative names already say, and hostnames long enough to overflow its
// sixty-four character limit are a way to have an order rejected for no
// reason.
func certificateRequest(key crypto.Signer, hosts []string) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{},
		DNSNames: hosts,
	}, key)
}

// encodeKeypair turns what the CA returned into the two PEM blobs a
// kubernetes.io/tls Secret holds. The whole chain is kept: a client that does
// not already have the intermediate cannot build a path without it.
func encodeKeypair(der [][]byte, key crypto.Signer) (*Keypair, error) {
	if len(der) == 0 {
		return nil, errors.New("the CA returned no certificate")
	}
	var chain []byte
	for _, block := range der {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block})...)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshalling the certificate key: %w", err)
	}
	return &Keypair{
		CertPEM: chain,
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// canonicalHosts reduces the requested hosts to the form an order names them
// in, dropping empties and duplicates and leaving the caller's slice alone.
func canonicalHosts(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}
