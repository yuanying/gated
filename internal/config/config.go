// Package config holds gated's startup configuration: the flag definitions,
// the parsed values, and the rules that decide whether those values can be
// started with.
//
// Validation is a pure function over the struct. It touches neither the
// filesystem nor the API server, so every rule is covered by a table test.
package config

import (
	"flag"
	"time"

	"github.com/yuanying/gated/internal/authn/connector"
)

// Config is the complete startup configuration of a gated process.
//
// The repeatable flags — the Services and addresses an Ingress's status is
// published from — are slices, so a Config is not comparable. Everything else
// is a scalar, and adding a map here would take away the last thing that makes
// a whole configuration easy to assert on.
type Config struct {
	// HTTPAddr is the listen address for plain HTTP. It serves the ACME
	// HTTP-01 challenge and, for everything else, a redirect to HTTPS.
	HTTPAddr string
	// HTTPSAddr is the listen address for TLS-terminated traffic.
	HTTPSAddr string
	// MetricsAddr is the listen address for the Prometheus endpoint, or "0"
	// to disable it.
	MetricsAddr string
	// HealthProbeAddr is the listen address for the liveness and readiness
	// probes, or "0" to disable them.
	HealthProbeAddr string

	// IngressClass is the value of Ingress.spec.ingressClassName this
	// process takes responsibility for.
	IngressClass string

	ACME           ACME
	Auth           Auth
	LeaderElection LeaderElection
	Publish        Publish

	// AccessLog records one line per request (ADR 0031). On unless it is
	// switched off: a process that keeps no record of what passed through
	// it should be that way because somebody decided so.
	AccessLog bool

	// ShutdownDelay is how long gated keeps serving after it is asked to
	// stop, before it starts draining. Removing a Pod from a Service's
	// endpoints and sending it SIGTERM are independent, so a replica that
	// stops listening the moment it is signalled refuses the requests that
	// were routed to it in between. The image carries no shell, so this is
	// gated's own wait rather than a preStop hook's.
	ShutdownDelay time.Duration

	// ChallengeSecretNamespace is where the HTTP-01 challenge tokens are
	// written so that every replica can answer them (ADR 0006).
	ChallengeSecretNamespace string
}

// Publish names where the external addresses written into the status of the
// Ingresses gated is responsible for come from (ADR 0032).
//
// The two are added together. Naming neither is the way to say that gated
// should not write the status at all, and is not a startup failure: gated does
// everything else without knowing how it is published.
type Publish struct {
	// Services are read for their status.loadBalancer.ingress[].
	Services ServiceRefs
	// Addresses are written as they stand, for a deployment that is not
	// published through a Service at all.
	Addresses Addresses
}

// IsZero reports whether nothing at all was named to publish.
func (p Publish) IsZero() bool { return len(p.Services) == 0 && len(p.Addresses) == 0 }

// ACME configures the built-in ACME client (ADR 0005).
type ACME struct {
	// DirectoryURL is the ACME directory to order certificates from.
	DirectoryURL string
	// Email is the contact address registered with the ACME account.
	Email string
	// AccountSecret holds the ACME account key, shared across replicas.
	AccountSecret SecretRef
}

// Auth configures the central authentication host and the identity providers
// behind it (ADR 0003).
type Auth struct {
	// Host is the single hostname that owns the login flow. Protected hosts
	// redirect here and are handed back a host-scoped session cookie.
	Host string
	// SessionKeySecret holds the HMAC key the session cookies are signed
	// with, shared across replicas.
	SessionKeySecret SecretRef
	// SessionTTL is how long a session cookie stays valid. A signed cookie
	// cannot be revoked (ADR 0003), so this is the only thing that ends
	// one.
	SessionTTL time.Duration

	GitHub GitHubClient
	Google GoogleClient
}

// GitHubClient is the GitHub OAuth application and the deployment of GitHub it
// belongs to.
type GitHubClient struct {
	OAuthClient
	// BaseURL is where the OAuth endpoints live. It is a setting so that
	// GitHub Enterprise, and the mock provider the end-to-end tests run
	// against, can be pointed at instead.
	BaseURL string
	// APIURL is the root of the REST API.
	APIURL string
}

// GoogleClient is the Google OAuth client and the issuer it belongs to.
type GoogleClient struct {
	OAuthClient
	// Issuer is the OpenID Connect issuer. It is a setting for the same
	// reason as GitHub's endpoints.
	Issuer string
}

// OAuthClient is the client registration of one identity provider.
type OAuthClient struct {
	ClientID        string
	ClientSecretRef SecretKeyRef
}

// IsZero reports whether the provider is left unconfigured.
func (c OAuthClient) IsZero() bool {
	return c.ClientID == "" && c.ClientSecretRef.IsZero()
}

// LeaderElection configures the Lease-based election that limits certificate
// issuance to a single replica (ADR 0006).
type LeaderElection struct {
	Enabled       bool
	ID            string
	Namespace     string
	LeaseDuration time.Duration
	RenewDeadline time.Duration
	RetryPeriod   time.Duration
}

// Default returns the configuration gated starts from before flags are parsed.
//
// Nothing that names a concrete deployment — a hostname, an address, an
// account, a namespace — carries a default. Those must be supplied, so that a
// misconfigured process refuses to start rather than silently reaching into
// whatever the default happened to name.
func Default() Config {
	return Config{
		HTTPAddr:        ":8080",
		HTTPSAddr:       ":8443",
		MetricsAddr:     ":9090",
		HealthProbeAddr: ":9091",
		IngressClass:    "gated",
		AccessLog:       true,
		// Long enough for an endpoint removal to reach the kube-proxy of
		// every node, short enough to stay well inside the grace period
		// the Deployment allows.
		ShutdownDelay: 5 * time.Second,
		Auth: Auth{
			SessionTTL: 12 * time.Hour,
			GitHub: GitHubClient{
				BaseURL: connector.DefaultGitHubBaseURL,
				APIURL:  connector.DefaultGitHubAPIURL,
			},
			Google: GoogleClient{Issuer: connector.DefaultGoogleIssuer},
		},
		LeaderElection: LeaderElection{
			Enabled:       true,
			ID:            "gated-leader-election",
			LeaseDuration: 15 * time.Second,
			RenewDeadline: 10 * time.Second,
			RetryPeriod:   2 * time.Second,
		},
	}
}

// NewFlagSet returns a flag set that reports parse errors to the caller
// instead of exiting the process, so that main can decide how to report them.
func NewFlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}

// AddFlags binds every field of c to a flag in fs.
func (c *Config) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.HTTPAddr, "http-addr", c.HTTPAddr,
		"Listen address for plain HTTP. Serves ACME HTTP-01 challenges and redirects everything else to HTTPS.")
	fs.StringVar(&c.HTTPSAddr, "https-addr", c.HTTPSAddr,
		"Listen address for TLS-terminated traffic.")
	fs.StringVar(&c.MetricsAddr, "metrics-addr", c.MetricsAddr,
		`Listen address for the Prometheus metrics endpoint, or "0" to disable it.`)
	fs.StringVar(&c.HealthProbeAddr, "health-probe-addr", c.HealthProbeAddr,
		`Listen address for the health and readiness probes, or "0" to disable them.`)
	fs.StringVar(&c.IngressClass, "ingress-class", c.IngressClass,
		"Value of Ingress.spec.ingressClassName this controller is responsible for.")

	fs.StringVar(&c.ACME.DirectoryURL, "acme-directory-url", c.ACME.DirectoryURL,
		"ACME directory URL to order certificates from. Required.")
	fs.StringVar(&c.ACME.Email, "acme-email", c.ACME.Email,
		"Contact address registered with the ACME account. Required.")
	fs.Var(&c.ACME.AccountSecret, "acme-account-secret",
		"Secret holding the ACME account key, as namespace/name. Created if missing. Required.")

	fs.StringVar(&c.Auth.Host, "auth-host", c.Auth.Host,
		"Hostname of the central authentication host, for example auth.example.com. Required.")
	fs.Var(&c.Auth.SessionKeySecret, "session-key-secret",
		"Secret holding the session cookie signing key, as namespace/name. Created if missing. Required.")
	fs.DurationVar(&c.Auth.SessionTTL, "session-ttl", c.Auth.SessionTTL,
		"How long a session cookie stays valid. A signed cookie cannot be revoked, so keep it short.")
	fs.StringVar(&c.Auth.GitHub.ClientID, "github-client-id", c.Auth.GitHub.ClientID,
		"OAuth client ID of the GitHub application.")
	fs.Var(&c.Auth.GitHub.ClientSecretRef, "github-client-secret-ref",
		"Secret entry holding the GitHub OAuth client secret, as namespace/name/key.")
	fs.StringVar(&c.Auth.GitHub.BaseURL, "github-base-url", c.Auth.GitHub.BaseURL,
		"Where GitHub's OAuth endpoints live. Change it for GitHub Enterprise.")
	fs.StringVar(&c.Auth.GitHub.APIURL, "github-api-url", c.Auth.GitHub.APIURL,
		"Root of GitHub's REST API. Change it for GitHub Enterprise.")
	fs.StringVar(&c.Auth.Google.ClientID, "google-client-id", c.Auth.Google.ClientID,
		"OAuth client ID of the Google application.")
	fs.Var(&c.Auth.Google.ClientSecretRef, "google-client-secret-ref",
		"Secret entry holding the Google OAuth client secret, as namespace/name/key.")
	fs.StringVar(&c.Auth.Google.Issuer, "google-issuer", c.Auth.Google.Issuer,
		"OpenID Connect issuer of the Google accounts to accept.")

	fs.Var(&c.Publish.Services, "publish-service",
		"Service whose external addresses are written into the status of the Ingresses gated is responsible for, as namespace/name. Repeatable.")
	fs.Var(&c.Publish.Addresses, "publish-address",
		"Address or hostname written into the status of the Ingresses gated is responsible for. Repeatable, and added to whatever --publish-service resolves to.")
	fs.BoolVar(&c.AccessLog, "access-log", c.AccessLog,
		"Write one line per request. The query string, the Authorization header and cookies are never written.")
	fs.DurationVar(&c.ShutdownDelay, "shutdown-delay", c.ShutdownDelay,
		"How long to keep serving after being asked to stop, so that this replica's removal from the endpoints has time to spread.")

	fs.StringVar(&c.ChallengeSecretNamespace, "challenge-secret-namespace", c.ChallengeSecretNamespace,
		"Namespace the ACME HTTP-01 challenge tokens are written to. Required.")

	fs.BoolVar(&c.LeaderElection.Enabled, "leader-elect", c.LeaderElection.Enabled,
		"Elect a leader. Only the leader orders certificates; every replica proxies and answers challenges.")
	fs.StringVar(&c.LeaderElection.ID, "leader-election-id", c.LeaderElection.ID,
		"Name of the Lease used for leader election.")
	fs.StringVar(&c.LeaderElection.Namespace, "leader-election-namespace", c.LeaderElection.Namespace,
		"Namespace of the leader election Lease. Required unless --leader-elect=false.")
	fs.DurationVar(&c.LeaderElection.LeaseDuration, "leader-election-lease-duration", c.LeaderElection.LeaseDuration,
		"How long a non-leader waits before attempting to acquire leadership.")
	fs.DurationVar(&c.LeaderElection.RenewDeadline, "leader-election-renew-deadline", c.LeaderElection.RenewDeadline,
		"How long the leader retries renewing its lease before giving it up.")
	fs.DurationVar(&c.LeaderElection.RetryPeriod, "leader-election-retry-period", c.LeaderElection.RetryPeriod,
		"How long clients wait between attempts at acquiring or renewing the lease.")
}
