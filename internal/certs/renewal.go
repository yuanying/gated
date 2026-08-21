// Package certs decides whether a certificate has to be replaced.
//
// Nothing here knows about Kubernetes. The input is the PEM a
// kubernetes.io/tls Secret holds, the hosts that have to be served and the
// current time; the output is a verdict and the reason for it. That keeps
// every boundary — the exact expiry instant, a subject alternative name that
// no longer covers a host, material that does not parse — reachable from a
// table test without an API server (ADR 0007).
package certs

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// Material is the certificate and its private key, in the PEM form a
// kubernetes.io/tls Secret holds them in (ADR 0005). A nil *Material means
// there is no Secret at all.
type Material struct {
	CertPEM []byte
	KeyPEM  []byte
}

// Reason names why a verdict came out the way it did. It is short enough to
// put in an event and stable enough to assert on.
type Reason string

const (
	// ReasonUpToDate says the certificate in place serves every host and
	// has time left.
	ReasonUpToDate Reason = "UpToDate"
	// ReasonNoHosts says nothing was asked for, so there is nothing to
	// obtain and nothing to serve.
	ReasonNoHosts Reason = "NoHosts"
	// ReasonMissing says there is no certificate, or no key to go with it.
	ReasonMissing Reason = "Missing"
	// ReasonMalformed says what is there cannot be read as a keypair.
	ReasonMalformed Reason = "Malformed"
	// ReasonExpired says the certificate's validity has run out.
	ReasonExpired Reason = "Expired"
	// ReasonNotYetValid says the certificate's validity has not begun,
	// which in practice means the clocks disagree.
	ReasonNotYetValid Reason = "NotYetValid"
	// ReasonHostsNotCovered says the certificate does not name every host
	// it would have to serve.
	ReasonHostsNotCovered Reason = "HostsNotCovered"
	// ReasonExpiringSoon says the certificate still works but has less time
	// left than the policy wants to keep in hand.
	ReasonExpiringSoon Reason = "ExpiringSoon"
)

// Decision is the verdict on one Secret.
//
// Renew and Usable are independent on purpose. A certificate with a week left
// is both: it has to be replaced, and until the replacement arrives it is
// still what the listener serves. Keeping the two apart is what lets a failed
// renewal leave a working host working, which ADR 0005 requires.
type Decision struct {
	// Renew says a new certificate has to be obtained.
	Renew bool
	// Usable says the material in place can still serve every required
	// host right now.
	Usable bool
	// Reason is the deciding condition.
	Reason Reason
	// Detail spells the reason out for a log line or an event.
	Detail string
	// RenewAt is when renewal becomes due, zero when there is no readable
	// certificate to compute it from.
	RenewAt time.Time
	// NotAfter is the expiry of the certificate in place, zero when there
	// is no readable certificate.
	NotAfter time.Time
}

// Policy is how much of a certificate's life has to remain before it is
// replaced.
type Policy struct {
	// LifetimeDivisor renews once less than a 1/LifetimeDivisor of the
	// certificate's total lifetime is left.
	LifetimeDivisor int
	// MinRemaining is the floor under that fraction: however long the
	// certificate lives, renewal starts at least this far ahead of expiry.
	MinRemaining time.Duration
}

// DefaultPolicy renews with a third of the lifetime left, and never with less
// than thirty days in hand. For the ninety day certificates ACME issues these
// two say the same thing, which leaves a month of failed attempts before a
// host goes dark.
func DefaultPolicy() Policy {
	return Policy{LifetimeDivisor: 3, MinRemaining: 30 * 24 * time.Hour}
}

// Threshold is how much validity has to remain before renewal is due.
//
// The floor is capped at half the lifetime. Without that cap a certificate
// shorter than the floor would be due for renewal the instant it was issued,
// and the retry loop would spend an issuance rate limit going nowhere.
func (p Policy) Threshold(lifetime time.Duration) time.Duration {
	if lifetime <= 0 {
		return 0
	}
	divisor := p.LifetimeDivisor
	if divisor <= 0 {
		divisor = 1
	}
	threshold := lifetime / time.Duration(divisor)
	if threshold < p.MinRemaining {
		threshold = p.MinRemaining
	}
	if half := lifetime / 2; threshold > half {
		threshold = half
	}
	return threshold
}

// Evaluate applies the default policy.
func Evaluate(m *Material, hosts []string, now time.Time) Decision {
	return DefaultPolicy().Evaluate(m, hosts, now)
}

// Evaluate decides what to do about one Secret.
func (p Policy) Evaluate(m *Material, hosts []string, now time.Time) Decision {
	wanted := canonicalHosts(hosts)
	if len(wanted) == 0 {
		return Decision{
			Reason: ReasonNoHosts,
			Detail: "no host is asked for, so there is nothing to obtain",
		}
	}

	if m == nil || len(m.CertPEM) == 0 || len(m.KeyPEM) == 0 {
		return Decision{
			Renew:  true,
			Reason: ReasonMissing,
			Detail: fmt.Sprintf("no certificate and key are stored for %s", strings.Join(wanted, ", ")),
		}
	}

	leaf, err := parseLeaf(*m)
	if err != nil {
		return Decision{
			Renew:  true,
			Reason: ReasonMalformed,
			Detail: fmt.Sprintf("the stored certificate cannot be read: %v", err),
		}
	}

	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	threshold := p.Threshold(lifetime)
	base := Decision{
		RenewAt:  leaf.NotAfter.Add(-threshold),
		NotAfter: leaf.NotAfter,
	}

	// Expiry comes before coverage. Both mean a new certificate, and an
	// expired one is the more urgent thing to read in an event.
	if !now.Before(leaf.NotAfter) {
		base.Renew = true
		base.Reason = ReasonExpired
		base.Detail = fmt.Sprintf("the stored certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
		return base
	}
	if now.Before(leaf.NotBefore) {
		base.Renew = true
		base.Reason = ReasonNotYetValid
		base.Detail = fmt.Sprintf("the stored certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
		return base
	}

	if missing := notCovered(leaf, wanted); len(missing) > 0 {
		base.Renew = true
		base.Reason = ReasonHostsNotCovered
		base.Detail = fmt.Sprintf("the stored certificate does not cover %s", strings.Join(missing, ", "))
		return base
	}

	base.Usable = true
	if remaining := leaf.NotAfter.Sub(now); remaining < threshold {
		base.Renew = true
		base.Reason = ReasonExpiringSoon
		base.Detail = fmt.Sprintf("the stored certificate expires at %s, which is inside the %s renewal window",
			leaf.NotAfter.UTC().Format(time.RFC3339), threshold)
		return base
	}

	base.Reason = ReasonUpToDate
	base.Detail = fmt.Sprintf("the stored certificate covers every host and is valid until %s",
		leaf.NotAfter.UTC().Format(time.RFC3339))
	return base
}

// parseLeaf reads the end-entity certificate, checking on the way that the
// stored key is the one that belongs to it. A Secret holding a certificate and
// somebody else's key is unusable, and saying so here means the listener never
// has to discover it during a handshake.
func parseLeaf(m Material) (*x509.Certificate, error) {
	pair, err := tls.X509KeyPair(m.CertPEM, m.KeyPEM)
	if err != nil {
		return nil, err
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("the PEM holds no certificate")
	}
	return x509.ParseCertificate(pair.Certificate[0])
}

// notCovered lists the hosts the certificate does not answer for, in the order
// they were asked for.
//
// Extra names in the certificate are not a reason to replace it. A superset
// still serves every host that is asked for, and reissuing to shrink the set
// spends an issuance rate limit on something no client can observe.
func notCovered(leaf *x509.Certificate, wanted []string) []string {
	var missing []string
	for _, host := range wanted {
		if leaf.VerifyHostname(host) != nil {
			missing = append(missing, host)
		}
	}
	return missing
}

// canonicalHosts reduces the requested hosts to the form names are compared
// in — lower case, without the root label's trailing dot — dropping empties
// and duplicates and leaving the caller's slice alone.
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
