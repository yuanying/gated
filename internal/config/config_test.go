package config_test

import (
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/yuanying/gated/internal/config"
)

// validConfig returns a configuration that must pass validation. Every test
// case starts from this and breaks exactly one thing, so a failure names the
// rule that broke.
func validConfig() config.Config {
	c := config.Default()
	c.IngressClass = "gated"
	c.ACME.DirectoryURL = "https://acme.example.com/directory"
	c.ACME.Email = "admin@example.com"
	c.ACME.AccountSecret = config.SecretRef{Namespace: "gated-system", Name: "acme-account"}
	c.Auth.Host = "auth.example.com"
	c.Auth.SessionKeySecret = config.SecretRef{Namespace: "gated-system", Name: "session-key"}
	c.Auth.GitHub.ClientID = "client-id"
	c.Auth.GitHub.ClientSecretRef = config.SecretKeyRef{Namespace: "gated-system", Name: "github-oauth", Key: "clientSecret"}
	c.LeaderElection.Namespace = "gated-system"
	c.ChallengeSecretNamespace = "gated-system"
	return c
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*config.Config)
		invalid []string // flags expected to be reported, sorted
	}{
		{
			name:   "fully specified configuration is valid",
			mutate: func(*config.Config) {},
		},
		{
			name:    "http addr must not be empty",
			mutate:  func(c *config.Config) { c.HTTPAddr = "" },
			invalid: []string{"http-addr"},
		},
		{
			name:    "https addr must carry a numeric port",
			mutate:  func(c *config.Config) { c.HTTPSAddr = ":https" },
			invalid: []string{"https-addr"},
		},
		{
			name:    "https addr must not be a bare host",
			mutate:  func(c *config.Config) { c.HTTPSAddr = "0.0.0.0" },
			invalid: []string{"https-addr"},
		},
		{
			name:   "metrics addr may be disabled with 0",
			mutate: func(c *config.Config) { c.MetricsAddr = "0" },
		},
		{
			name:   "health probe addr may be disabled with 0",
			mutate: func(c *config.Config) { c.HealthProbeAddr = "0" },
		},
		{
			name:    "ingress class is required",
			mutate:  func(c *config.Config) { c.IngressClass = "" },
			invalid: []string{"ingress-class"},
		},
		{
			name:    "ingress class must be a DNS subdomain",
			mutate:  func(c *config.Config) { c.IngressClass = "Gated Class" },
			invalid: []string{"ingress-class"},
		},
		{
			name:    "acme directory url is required",
			mutate:  func(c *config.Config) { c.ACME.DirectoryURL = "" },
			invalid: []string{"acme-directory-url"},
		},
		{
			name:    "acme directory url must be absolute",
			mutate:  func(c *config.Config) { c.ACME.DirectoryURL = "/directory" },
			invalid: []string{"acme-directory-url"},
		},
		{
			name:    "acme directory url must be http or https",
			mutate:  func(c *config.Config) { c.ACME.DirectoryURL = "ftp://acme.example.com/directory" },
			invalid: []string{"acme-directory-url"},
		},
		{
			name:    "acme email is required",
			mutate:  func(c *config.Config) { c.ACME.Email = "" },
			invalid: []string{"acme-email"},
		},
		{
			name:    "acme email must look like a mail address",
			mutate:  func(c *config.Config) { c.ACME.Email = "admin" },
			invalid: []string{"acme-email"},
		},
		{
			name:    "acme account secret is required",
			mutate:  func(c *config.Config) { c.ACME.AccountSecret = config.SecretRef{} },
			invalid: []string{"acme-account-secret"},
		},
		{
			name:    "acme account secret namespace must be a DNS label",
			mutate:  func(c *config.Config) { c.ACME.AccountSecret.Namespace = "Gated_System" },
			invalid: []string{"acme-account-secret"},
		},
		{
			name:    "auth host is required",
			mutate:  func(c *config.Config) { c.Auth.Host = "" },
			invalid: []string{"auth-host"},
		},
		{
			name:    "auth host must not carry a scheme",
			mutate:  func(c *config.Config) { c.Auth.Host = "https://auth.example.com" },
			invalid: []string{"auth-host"},
		},
		{
			name:    "auth host must not carry a path",
			mutate:  func(c *config.Config) { c.Auth.Host = "auth.example.com/login" },
			invalid: []string{"auth-host"},
		},
		{
			name:   "auth host may carry a port",
			mutate: func(c *config.Config) { c.Auth.Host = "auth.example.com:8443" },
		},
		{
			name:    "auth host port must be numeric",
			mutate:  func(c *config.Config) { c.Auth.Host = "auth.example.com:https" },
			invalid: []string{"auth-host"},
		},
		{
			name:    "session key secret is required",
			mutate:  func(c *config.Config) { c.Auth.SessionKeySecret = config.SecretRef{} },
			invalid: []string{"session-key-secret"},
		},
		{
			name: "at least one identity provider must be configured",
			mutate: func(c *config.Config) {
				c.Auth.GitHub = config.GitHubClient{}
				c.Auth.Google = config.GoogleClient{}
			},
			invalid: []string{"github-client-id", "google-client-id"},
		},
		{
			name: "google alone is enough",
			mutate: func(c *config.Config) {
				c.Auth.GitHub = config.GitHubClient{}
				c.Auth.Google = config.GoogleClient{OAuthClient: config.OAuthClient{
					ClientID:        "client-id",
					ClientSecretRef: config.SecretKeyRef{Namespace: "gated-system", Name: "google-oauth", Key: "clientSecret"},
				}}
			},
		},
		{
			name:    "the session lifetime must be positive",
			mutate:  func(c *config.Config) { c.Auth.SessionTTL = 0 },
			invalid: []string{"session-ttl"},
		},
		{
			name:    "the session lifetime must not run backwards",
			mutate:  func(c *config.Config) { c.Auth.SessionTTL = -time.Hour },
			invalid: []string{"session-ttl"},
		},
		{
			name:    "the GitHub endpoints must be absolute",
			mutate:  func(c *config.Config) { c.Auth.GitHub.BaseURL = "github.example.com" },
			invalid: []string{"github-base-url"},
		},
		{
			name:    "the GitHub API must not be a path",
			mutate:  func(c *config.Config) { c.Auth.GitHub.APIURL = "/api/v3" },
			invalid: []string{"github-api-url"},
		},
		{
			name:   "an empty GitHub endpoint falls back to github.com",
			mutate: func(c *config.Config) { c.Auth.GitHub.BaseURL, c.Auth.GitHub.APIURL = "", "" },
		},
		{
			name: "the Google issuer must be absolute",
			mutate: func(c *config.Config) {
				c.Auth.Google.ClientID = "client-id"
				c.Auth.Google.ClientSecretRef = config.SecretKeyRef{Namespace: "gated-system", Name: "google-oauth", Key: "clientSecret"}
				c.Auth.Google.Issuer = "accounts.example.com"
			},
			invalid: []string{"google-issuer"},
		},
		{
			name:   "the Google issuer is not checked when Google is not configured",
			mutate: func(c *config.Config) { c.Auth.Google.Issuer = "not a URL at all" },
		},
		{
			name:    "github client id without a secret reference is incomplete",
			mutate:  func(c *config.Config) { c.Auth.GitHub.ClientSecretRef = config.SecretKeyRef{} },
			invalid: []string{"github-client-secret-ref"},
		},
		{
			name: "github secret reference without a client id is incomplete",
			mutate: func(c *config.Config) {
				c.Auth.GitHub.ClientID = ""
			},
			invalid: []string{"github-client-id"},
		},
		{
			name:    "github secret reference needs a key",
			mutate:  func(c *config.Config) { c.Auth.GitHub.ClientSecretRef.Key = "" },
			invalid: []string{"github-client-secret-ref"},
		},
		{
			name: "google client id without a secret reference is incomplete",
			mutate: func(c *config.Config) {
				c.Auth.Google.ClientID = "client-id"
			},
			invalid: []string{"google-client-secret-ref"},
		},
		{
			name:    "challenge secret namespace is required",
			mutate:  func(c *config.Config) { c.ChallengeSecretNamespace = "" },
			invalid: []string{"challenge-secret-namespace"},
		},
		{
			name:    "challenge secret namespace must be a DNS label",
			mutate:  func(c *config.Config) { c.ChallengeSecretNamespace = "gated system" },
			invalid: []string{"challenge-secret-namespace"},
		},
		{
			name:    "leader election namespace is required while leader election is on",
			mutate:  func(c *config.Config) { c.LeaderElection.Namespace = "" },
			invalid: []string{"leader-election-namespace"},
		},
		{
			name: "leader election namespace is not required once leader election is off",
			mutate: func(c *config.Config) {
				c.LeaderElection.Enabled = false
				c.LeaderElection.Namespace = ""
			},
		},
		{
			name:    "leader election id is required",
			mutate:  func(c *config.Config) { c.LeaderElection.ID = "" },
			invalid: []string{"leader-election-id"},
		},
		{
			name:    "lease duration must be positive",
			mutate:  func(c *config.Config) { c.LeaderElection.LeaseDuration = 0 },
			invalid: []string{"leader-election-lease-duration"},
		},
		{
			name:    "renew deadline must be shorter than the lease duration",
			mutate:  func(c *config.Config) { c.LeaderElection.RenewDeadline = c.LeaderElection.LeaseDuration },
			invalid: []string{"leader-election-renew-deadline"},
		},
		{
			name:    "retry period must be shorter than the renew deadline",
			mutate:  func(c *config.Config) { c.LeaderElection.RetryPeriod = c.LeaderElection.RenewDeadline },
			invalid: []string{"leader-election-retry-period"},
		},
		{
			// Naming neither is how a deployment says "do not write
			// the status at all" (ADR 0032), so it is not a mistake.
			name:   "publishing no address at all is a configuration",
			mutate: func(*config.Config) {},
		},
		{
			name: "a published Service and a published address may be given together",
			mutate: func(c *config.Config) {
				c.Publish.Services = config.ServiceRefs{{Namespace: "gated-system", Name: "gated-v6"}}
				c.Publish.Addresses = config.Addresses{"203.0.113.10"}
			},
		},
		{
			name: "a published Service names a namespace and a name",
			mutate: func(c *config.Config) {
				c.Publish.Services = config.ServiceRefs{{Namespace: "gated system", Name: "gated-v4"}}
			},
			invalid: []string{"publish-service"},
		},
		{
			name: "a published Service without a name is incomplete",
			mutate: func(c *config.Config) {
				c.Publish.Services = config.ServiceRefs{{Namespace: "gated-system"}}
			},
			invalid: []string{"publish-service"},
		},
		{
			name: "a published address is an address or a hostname",
			mutate: func(c *config.Config) {
				c.Publish.Addresses = config.Addresses{"not an address"}
			},
			invalid: []string{"publish-address"},
		},
		{
			name: "a published address may be a hostname",
			mutate: func(c *config.Config) {
				c.Publish.Addresses = config.Addresses{"gated.example.com"}
			},
		},
		{
			name: "a published address may be an IPv6 address",
			mutate: func(c *config.Config) {
				c.Publish.Addresses = config.Addresses{"2001:db8::1"}
			},
		},
		{
			name:    "an empty published address says nothing",
			mutate:  func(c *config.Config) { c.Publish.Addresses = config.Addresses{""} },
			invalid: []string{"publish-address"},
		},
		{
			name:    "the shutdown delay must not run backwards",
			mutate:  func(c *config.Config) { c.ShutdownDelay = -time.Second },
			invalid: []string{"shutdown-delay"},
		},
		{
			name:   "a shutdown delay of zero switches the wait off",
			mutate: func(c *config.Config) { c.ShutdownDelay = 0 },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mutate(&c)

			err := c.Validate()
			got := config.InvalidFlags(err)
			sort.Strings(got)

			want := tt.invalid
			sort.Strings(want)

			if len(got) != len(want) {
				t.Fatalf("invalid flags = %v, want %v (err: %v)", got, want, err)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("invalid flags = %v, want %v (err: %v)", got, want, err)
				}
			}
			if len(want) == 0 && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
			if len(want) > 0 && err == nil {
				t.Fatal("Validate() = nil, want an error")
			}
		})
	}
}

func TestDefaultCarriesNoEnvironmentSpecificValues(t *testing.T) {
	c := config.Default()

	// Anything that names a concrete deployment must be supplied by the
	// operator; a default here would leak one environment into every other.
	if c.ACME.DirectoryURL != "" {
		t.Errorf("ACME.DirectoryURL default = %q, want empty", c.ACME.DirectoryURL)
	}
	if c.ACME.Email != "" {
		t.Errorf("ACME.Email default = %q, want empty", c.ACME.Email)
	}
	if !c.ACME.AccountSecret.IsZero() {
		t.Errorf("ACME.AccountSecret default = %v, want zero", c.ACME.AccountSecret)
	}
	if c.Auth.Host != "" {
		t.Errorf("Auth.Host default = %q, want empty", c.Auth.Host)
	}
	if !c.Auth.SessionKeySecret.IsZero() {
		t.Errorf("Auth.SessionKeySecret default = %v, want zero", c.Auth.SessionKeySecret)
	}
	if !c.Auth.GitHub.IsZero() || !c.Auth.Google.IsZero() {
		t.Errorf("identity provider defaults = %v/%v, want zero", c.Auth.GitHub, c.Auth.Google)
	}
	if c.ChallengeSecretNamespace != "" {
		t.Errorf("ChallengeSecretNamespace default = %q, want empty", c.ChallengeSecretNamespace)
	}
	if c.LeaderElection.Namespace != "" {
		t.Errorf("LeaderElection.Namespace default = %q, want empty", c.LeaderElection.Namespace)
	}

	// Listen addresses bind the wildcard address, which is the same everywhere.
	for flag, addr := range map[string]string{
		"http-addr":         c.HTTPAddr,
		"https-addr":        c.HTTPSAddr,
		"metrics-addr":      c.MetricsAddr,
		"health-probe-addr": c.HealthProbeAddr,
	} {
		if len(addr) == 0 || addr[0] != ':' {
			t.Errorf("--%s default = %q, want a wildcard bind address", flag, addr)
		}
	}
	if !c.LeaderElection.Enabled {
		t.Error("leader election default = off, want on")
	}

	// Where gated is published is environment specific and has no default;
	// whether it records what passes through it is not, and recording is
	// the answer that does not have to be remembered (ADR 0031).
	if len(c.Publish.Services) != 0 || len(c.Publish.Addresses) != 0 {
		t.Errorf("publish defaults = %v/%v, want empty", c.Publish.Services, c.Publish.Addresses)
	}
	if !c.AccessLog {
		t.Error("--access-log default = off, want on")
	}
	if c.ShutdownDelay <= 0 {
		t.Errorf("--shutdown-delay default = %v, want a wait long enough for an endpoint removal to spread", c.ShutdownDelay)
	}
	if c.LeaderElection.LeaseDuration <= c.LeaderElection.RenewDeadline ||
		c.LeaderElection.RenewDeadline <= c.LeaderElection.RetryPeriod ||
		c.LeaderElection.RetryPeriod <= 0 {
		t.Errorf("leader election timing defaults are not ordered: %v", c.LeaderElection)
	}
}

func TestSecretRefParsing(t *testing.T) {
	tests := []struct {
		in      string
		want    config.SecretRef
		wantErr bool
	}{
		{in: "gated-system/acme-account", want: config.SecretRef{Namespace: "gated-system", Name: "acme-account"}},
		{in: "acme-account", wantErr: true},
		{in: "gated-system/", wantErr: true},
		{in: "/acme-account", wantErr: true},
		{in: "a/b/c", wantErr: true},
		{in: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			var got config.SecretRef
			err := got.Set(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Set(%q) = nil, want an error", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("Set(%q) = %v, want nil", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("Set(%q) = %v, want %v", tt.in, got, tt.want)
			}
			if got.String() != tt.in {
				t.Fatalf("String() = %q, want %q", got.String(), tt.in)
			}
		})
	}
}

func TestSecretKeyRefParsing(t *testing.T) {
	tests := []struct {
		in      string
		want    config.SecretKeyRef
		wantErr bool
	}{
		{in: "gated-system/github-oauth/clientSecret", want: config.SecretKeyRef{Namespace: "gated-system", Name: "github-oauth", Key: "clientSecret"}},
		{in: "gated-system/github-oauth", wantErr: true},
		{in: "gated-system/github-oauth/", wantErr: true},
		{in: "a/b/c/d", wantErr: true},
		{in: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			var got config.SecretKeyRef
			err := got.Set(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Set(%q) = nil, want an error", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("Set(%q) = %v, want nil", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("Set(%q) = %v, want %v", tt.in, got, tt.want)
			}
			if got.String() != tt.in {
				t.Fatalf("String() = %q, want %q", got.String(), tt.in)
			}
		})
	}
}

// Every reported problem must name the flag that carries it, otherwise the
// operator has to guess which of thirty flags to fix.
func TestValidateErrorNamesTheFlag(t *testing.T) {
	c := validConfig()
	c.Auth.Host = ""

	err := c.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want an error")
	}
	var fieldErr *config.FieldError
	if !errors.As(err, &fieldErr) {
		t.Fatalf("Validate() = %v, want an error wrapping *config.FieldError", err)
	}
	if fieldErr.Flag != "auth-host" {
		t.Fatalf("FieldError.Flag = %q, want %q", fieldErr.Flag, "auth-host")
	}
	if got := err.Error(); got == "" {
		t.Fatal("Validate() error message is empty")
	}
}

// AddFlags must round-trip: parsing the flags of a configuration produces the
// same configuration back.
func TestAddFlagsRoundTrip(t *testing.T) {
	want := validConfig()
	want.Auth.Google.ClientID = "google-client-id"
	want.Auth.Google.ClientSecretRef = config.SecretKeyRef{Namespace: "gated-system", Name: "google-oauth", Key: "clientSecret"}
	want.Publish.Services = config.ServiceRefs{
		{Namespace: "gated-system", Name: "gated-v4"},
		{Namespace: "gated-system", Name: "gated-v6"},
	}
	want.Publish.Addresses = config.Addresses{"203.0.113.10", "2001:db8::1"}
	want.AccessLog = false
	want.ShutdownDelay = 7 * time.Second
	want.LeaderElection.LeaseDuration = 20 * time.Second
	want.LeaderElection.RenewDeadline = 15 * time.Second
	want.LeaderElection.RetryPeriod = 3 * time.Second

	args := []string{
		"--ingress-class=" + want.IngressClass,
		"--acme-directory-url=" + want.ACME.DirectoryURL,
		"--acme-email=" + want.ACME.Email,
		"--acme-account-secret=" + want.ACME.AccountSecret.String(),
		"--auth-host=" + want.Auth.Host,
		"--session-key-secret=" + want.Auth.SessionKeySecret.String(),
		"--github-client-id=" + want.Auth.GitHub.ClientID,
		"--github-client-secret-ref=" + want.Auth.GitHub.ClientSecretRef.String(),
		"--google-client-id=" + want.Auth.Google.ClientID,
		"--google-client-secret-ref=" + want.Auth.Google.ClientSecretRef.String(),
		"--challenge-secret-namespace=" + want.ChallengeSecretNamespace,
		"--leader-election-namespace=" + want.LeaderElection.Namespace,
		"--leader-election-lease-duration=20s",
		"--leader-election-renew-deadline=15s",
		"--leader-election-retry-period=3s",
		// Repeatable, so that one process can publish the addresses of
		// more than one Service (ADR 0032).
		"--publish-service=gated-system/gated-v4",
		"--publish-service=gated-system/gated-v6",
		"--publish-address=203.0.113.10",
		"--publish-address=2001:db8::1",
		"--access-log=false",
		"--shutdown-delay=7s",
	}

	got, fs := config.Default(), config.NewFlagSet("gated")
	got.AddFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	// Compared field by field rather than with ==: the repeatable flags
	// collect into slices, which is what stops a Config from being
	// comparable.
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed config = %+v, want %+v", got, want)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestAddFlagsRejectsMalformedSecretRef(t *testing.T) {
	c, fs := config.Default(), config.NewFlagSet("gated")
	c.AddFlags(fs)
	fs.SetOutput(discard{})

	if err := fs.Parse([]string{"--acme-account-secret=acme-account"}); err == nil {
		t.Fatal("Parse() = nil, want an error for a secret reference without a namespace")
	}
}

func TestAddFlagsRejectsMalformedPublishService(t *testing.T) {
	for _, arg := range []string{"--publish-service=gated-v4", "--publish-service=gated-system/", "--publish-service="} {
		c, fs := config.Default(), config.NewFlagSet("gated")
		c.AddFlags(fs)
		fs.SetOutput(discard{})

		if err := fs.Parse([]string{arg}); err == nil {
			t.Errorf("Parse(%q) = nil, want an error for a Service reference that is not namespace/name", arg)
		}
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
