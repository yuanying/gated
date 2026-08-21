package config

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"strconv"
	"strings"

	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
)

// FieldError is a single validation failure, tied to the flag that carries the
// offending value. Reporting the flag rather than the struct field means the
// operator is told what to edit.
type FieldError struct {
	Flag string
	Msg  string
}

func (e *FieldError) Error() string { return "--" + e.Flag + ": " + e.Msg }

// InvalidFlags returns the flags reported by an error from Validate, in the
// order they were found. It returns nil for a nil error.
func InvalidFlags(err error) []string {
	var flags []string
	collectFlags(err, &flags)
	return flags
}

func collectFlags(err error, flags *[]string) {
	switch e := err.(type) {
	case nil:
		return
	case *FieldError:
		*flags = append(*flags, e.Flag)
	case interface{ Unwrap() []error }:
		for _, sub := range e.Unwrap() {
			collectFlags(sub, flags)
		}
	case interface{ Unwrap() error }:
		collectFlags(e.Unwrap(), flags)
	}
}

// Validate reports every problem it finds, not just the first, so that a
// misconfigured deployment can be fixed in one pass instead of one restart per
// mistake.
func (c Config) Validate() error {
	var errs []error
	report := func(flag, format string, args ...any) {
		errs = append(errs, &FieldError{Flag: flag, Msg: fmt.Sprintf(format, args...)})
	}

	c.validateAddrs(report)
	c.validateIngressClass(report)
	c.validateACME(report)
	c.validateAuth(report)
	c.validateChallenge(report)
	c.validateLeaderElection(report)

	return errors.Join(errs...)
}

type reportFunc func(flag, format string, args ...any)

func (c Config) validateAddrs(report reportFunc) {
	for _, a := range []struct {
		flag        string
		value       string
		disableable bool
	}{
		{flag: "http-addr", value: c.HTTPAddr},
		{flag: "https-addr", value: c.HTTPSAddr},
		{flag: "metrics-addr", value: c.MetricsAddr, disableable: true},
		{flag: "health-probe-addr", value: c.HealthProbeAddr, disableable: true},
	} {
		if a.disableable && a.value == "0" {
			continue
		}
		if err := validateListenAddr(a.value); err != nil {
			report(a.flag, "%v", err)
		}
	}
}

func validateListenAddr(addr string) error {
	if addr == "" {
		return errors.New("is required")
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q is not of the form [host]:port", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("%q does not carry a numeric port", addr)
	}
	return nil
}

func (c Config) validateIngressClass(report reportFunc) {
	if c.IngressClass == "" {
		report("ingress-class", "is required")
		return
	}
	if msgs := k8svalidation.IsDNS1123Subdomain(c.IngressClass); len(msgs) > 0 {
		report("ingress-class", "%q is not a valid IngressClass name: %s", c.IngressClass, strings.Join(msgs, "; "))
	}
}

func (c Config) validateACME(report reportFunc) {
	switch u, err := url.Parse(c.ACME.DirectoryURL); {
	case c.ACME.DirectoryURL == "":
		report("acme-directory-url", "is required")
	case err != nil:
		report("acme-directory-url", "%q is not a URL: %v", c.ACME.DirectoryURL, err)
	case u.Scheme != "http" && u.Scheme != "https":
		report("acme-directory-url", "%q must be an absolute http or https URL", c.ACME.DirectoryURL)
	case u.Host == "":
		report("acme-directory-url", "%q must be an absolute http or https URL", c.ACME.DirectoryURL)
	}

	if c.ACME.Email == "" {
		report("acme-email", "is required")
	} else if addr, err := mail.ParseAddress(c.ACME.Email); err != nil || addr.Address != c.ACME.Email {
		report("acme-email", "%q is not a bare mail address", c.ACME.Email)
	}

	validateSecretRef(report, "acme-account-secret", c.ACME.AccountSecret, true)
}

func (c Config) validateAuth(report reportFunc) {
	if err := validateAuthHost(c.Auth.Host); err != nil {
		report("auth-host", "%v", err)
	}

	validateSecretRef(report, "session-key-secret", c.Auth.SessionKeySecret, true)

	if c.Auth.SessionTTL <= 0 {
		report("session-ttl", "must be positive")
	}

	// Every protected host that is not world-readable ends in a redirect to
	// the central authentication host. With no provider behind it that
	// redirect is a dead end, so refuse to start instead.
	if c.Auth.GitHub.IsZero() && c.Auth.Google.IsZero() {
		report("github-client-id", "at least one identity provider must be configured")
		report("google-client-id", "at least one identity provider must be configured")
		return
	}

	validateOAuthClient(report, "github", c.Auth.GitHub.OAuthClient)
	if !c.Auth.GitHub.IsZero() {
		validateEndpoint(report, "github-base-url", c.Auth.GitHub.BaseURL)
		validateEndpoint(report, "github-api-url", c.Auth.GitHub.APIURL)
	}

	validateOAuthClient(report, "google", c.Auth.Google.OAuthClient)
	if !c.Auth.Google.IsZero() {
		validateEndpoint(report, "google-issuer", c.Auth.Google.Issuer)
	}
}

// validateEndpoint checks an identity provider's address. An empty one falls
// back to the provider's own endpoints, which is what the defaults name.
//
// Plain HTTP is allowed so that a mock provider inside a test cluster can be
// pointed at; a real deployment names an https address.
func validateEndpoint(report reportFunc, flag, endpoint string) {
	switch u, err := url.Parse(endpoint); {
	case endpoint == "":
		return
	case err != nil:
		report(flag, "%q is not a URL: %v", endpoint, err)
	case u.Scheme != "http" && u.Scheme != "https":
		report(flag, "%q must be an absolute http or https URL", endpoint)
	case u.Host == "":
		report(flag, "%q must be an absolute http or https URL", endpoint)
	}
}

func validateAuthHost(host string) error {
	if host == "" {
		return errors.New("is required")
	}
	if strings.Contains(host, "/") {
		return fmt.Errorf("%q must be a bare hostname, without a scheme or a path", host)
	}

	name := host
	if strings.Contains(host, ":") {
		h, port, err := net.SplitHostPort(host)
		if err != nil {
			return fmt.Errorf("%q is not of the form host[:port]", host)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("%q does not carry a numeric port", host)
		}
		name = h
	}
	if msgs := k8svalidation.IsDNS1123Subdomain(name); len(msgs) > 0 {
		return fmt.Errorf("%q is not a valid hostname: %s", host, strings.Join(msgs, "; "))
	}
	return nil
}

func validateOAuthClient(report reportFunc, provider string, client OAuthClient) {
	if client.IsZero() {
		return
	}
	if client.ClientID == "" {
		report(provider+"-client-id", "is required once %s is configured", provider)
	}
	validateSecretKeyRef(report, provider+"-client-secret-ref", client.ClientSecretRef, true)
}

func (c Config) validateChallenge(report reportFunc) {
	if c.ChallengeSecretNamespace == "" {
		report("challenge-secret-namespace", "is required")
		return
	}
	if msgs := k8svalidation.IsDNS1123Label(c.ChallengeSecretNamespace); len(msgs) > 0 {
		report("challenge-secret-namespace", "%q is not a valid namespace: %s",
			c.ChallengeSecretNamespace, strings.Join(msgs, "; "))
	}
}

func (c Config) validateLeaderElection(report reportFunc) {
	le := c.LeaderElection
	if !le.Enabled {
		return
	}

	if le.ID == "" {
		report("leader-election-id", "is required")
	} else if msgs := k8svalidation.IsDNS1123Subdomain(le.ID); len(msgs) > 0 {
		report("leader-election-id", "%q is not a valid Lease name: %s", le.ID, strings.Join(msgs, "; "))
	}

	if le.Namespace == "" {
		report("leader-election-namespace", "is required unless --leader-elect=false")
	} else if msgs := k8svalidation.IsDNS1123Label(le.Namespace); len(msgs) > 0 {
		report("leader-election-namespace", "%q is not a valid namespace: %s", le.Namespace, strings.Join(msgs, "; "))
	}

	if le.LeaseDuration <= 0 {
		report("leader-election-lease-duration", "must be positive")
	}
	if le.RenewDeadline <= 0 {
		report("leader-election-renew-deadline", "must be positive")
	}
	if le.RetryPeriod <= 0 {
		report("leader-election-retry-period", "must be positive")
	}

	// A renew deadline that reaches the lease duration lets the lease expire
	// while the leader still believes it holds it.
	if le.LeaseDuration > 0 && le.RenewDeadline > 0 && le.RenewDeadline >= le.LeaseDuration {
		report("leader-election-renew-deadline", "must be shorter than --leader-election-lease-duration")
	}
	if le.RenewDeadline > 0 && le.RetryPeriod > 0 && le.RetryPeriod >= le.RenewDeadline {
		report("leader-election-retry-period", "must be shorter than --leader-election-renew-deadline")
	}
}

func validateSecretRef(report reportFunc, flag string, ref SecretRef, required bool) {
	if ref.IsZero() {
		if required {
			report(flag, "is required, as namespace/name")
		}
		return
	}
	if msgs := k8svalidation.IsDNS1123Label(ref.Namespace); len(msgs) > 0 {
		report(flag, "namespace %q is not valid: %s", ref.Namespace, strings.Join(msgs, "; "))
	}
	if msgs := k8svalidation.IsDNS1123Subdomain(ref.Name); len(msgs) > 0 {
		report(flag, "name %q is not valid: %s", ref.Name, strings.Join(msgs, "; "))
	}
}

func validateSecretKeyRef(report reportFunc, flag string, ref SecretKeyRef, required bool) {
	if ref.IsZero() {
		if required {
			report(flag, "is required, as namespace/name/key")
		}
		return
	}
	if msgs := k8svalidation.IsDNS1123Label(ref.Namespace); len(msgs) > 0 {
		report(flag, "namespace %q is not valid: %s", ref.Namespace, strings.Join(msgs, "; "))
	}
	if msgs := k8svalidation.IsDNS1123Subdomain(ref.Name); len(msgs) > 0 {
		report(flag, "name %q is not valid: %s", ref.Name, strings.Join(msgs, "; "))
	}
	if ref.Key == "" {
		report(flag, "is missing the key, expected namespace/name/key")
	} else if msgs := k8svalidation.IsConfigMapKey(ref.Key); len(msgs) > 0 {
		report(flag, "key %q is not valid: %s", ref.Key, strings.Join(msgs, "; "))
	}
}
