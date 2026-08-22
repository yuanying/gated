package controller_test

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/yuanying/gated/internal/controller"
)

// The expiry is published per host, because a host is what a certificate is
// issued for and what somebody reads the number to find out about (ADR 0031).
func TestCertificateExpiryIsPublishedPerHost(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	metrics := controller.NewMetrics(registry)

	expiry := time.Unix(1800000000, 0)
	metrics.SetCertificateExpiry("apps", "web-tls", []string{"a.example.com", "b.example.com"}, expiry)

	const both = `
# HELP gated_certificate_not_after_timestamp_seconds When the certificate in place expires, as a Unix timestamp.
# TYPE gated_certificate_not_after_timestamp_seconds gauge
gated_certificate_not_after_timestamp_seconds{host="a.example.com",namespace="apps",secret="web-tls"} 1.8e+09
gated_certificate_not_after_timestamp_seconds{host="b.example.com",namespace="apps",secret="web-tls"} 1.8e+09
`
	if err := testutil.GatherAndCompare(registry, strings.NewReader(both), certificateExpiry); err != nil {
		t.Error(err)
	}

	// A host that has been taken off the certificate has no expiry to
	// report, and leaving the old one behind would have it alert on a
	// certificate nobody is renewing any more.
	metrics.SetCertificateExpiry("apps", "web-tls", []string{"a.example.com"}, expiry)

	const one = `
# HELP gated_certificate_not_after_timestamp_seconds When the certificate in place expires, as a Unix timestamp.
# TYPE gated_certificate_not_after_timestamp_seconds gauge
gated_certificate_not_after_timestamp_seconds{host="a.example.com",namespace="apps",secret="web-tls"} 1.8e+09
`
	if err := testutil.GatherAndCompare(registry, strings.NewReader(one), certificateExpiry); err != nil {
		t.Error(err)
	}
}

// A gauge that is never removed goes on reporting the last thing it was told
// for as long as the process runs, so what is gone has to be said to be gone.
func TestForgettingACertificateRemovesEverySeries(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	metrics := controller.NewMetrics(registry)

	metrics.SetCertificateExpiry("apps", "web-tls", []string{"a.example.com"}, time.Unix(1800000000, 0))
	metrics.SetCertificateRenewalFailures("apps", "web-tls", 3)
	metrics.SetCertificateExpiry("other", "other-tls", []string{"c.example.com"}, time.Unix(1800000000, 0))

	metrics.ForgetCertificate("apps", "web-tls")

	if got := testutil.CollectAndCount(registry, certificateExpiry); got != 1 {
		t.Errorf("%s has %d series, want only the certificate that is still there", certificateExpiry, got)
	}
	if got := testutil.CollectAndCount(registry, certificateFailures); got != 0 {
		t.Errorf("%s has %d series, want none", certificateFailures, got)
	}
}

// The failure count is the consecutive one: it says "this has been failing for
// a while", which is the thing worth waking somebody for (ADR 0014).
func TestRenewalFailuresAreReportedAndCleared(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	metrics := controller.NewMetrics(registry)

	metrics.SetCertificateRenewalFailures("apps", "web-tls", 3)
	const failing = `
# HELP gated_certificate_renewal_failures Consecutive failures to obtain the certificate for this Secret.
# TYPE gated_certificate_renewal_failures gauge
gated_certificate_renewal_failures{namespace="apps",secret="web-tls"} 3
`
	if err := testutil.GatherAndCompare(registry, strings.NewReader(failing), certificateFailures); err != nil {
		t.Error(err)
	}

	// Zero rather than absent: a series that disappears on success cannot
	// be told apart from one whose process died.
	metrics.SetCertificateRenewalFailures("apps", "web-tls", 0)
	const recovered = `
# HELP gated_certificate_renewal_failures Consecutive failures to obtain the certificate for this Secret.
# TYPE gated_certificate_renewal_failures gauge
gated_certificate_renewal_failures{namespace="apps",secret="web-tls"} 0
`
	if err := testutil.GatherAndCompare(registry, strings.NewReader(recovered), certificateFailures); err != nil {
		t.Error(err)
	}
}

// A role whose target does not resolve protects nothing, and what it meant to
// protect is served to everybody (ADR 0002). That is the alert.
func TestNetworkRoleResolutionIsReported(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	metrics := controller.NewMetrics(registry)

	metrics.SetNetworkRoleResolved("apps", "web", true)
	metrics.SetNetworkRoleResolved("apps", "broken", false)

	const want = `
# HELP gated_networkrole_target_resolved Whether this NetworkRole's targetRef names something gated could find.
# TYPE gated_networkrole_target_resolved gauge
gated_networkrole_target_resolved{name="broken",namespace="apps"} 0
gated_networkrole_target_resolved{name="web",namespace="apps"} 1
`
	if err := testutil.GatherAndCompare(registry, strings.NewReader(want), roleResolved); err != nil {
		t.Error(err)
	}

	metrics.ForgetNetworkRole("apps", "broken")
	if got := testutil.CollectAndCount(registry, roleResolved); got != 1 {
		t.Errorf("%s has %d series, want only the role that still exists", roleResolved, got)
	}
}

// The reconcilers are wired without metrics in the tests that are about what
// they write to the API server, so every call has to survive a nil.
func TestNoMetricsIsNotAFailure(t *testing.T) {
	var metrics *controller.Metrics

	metrics.SetCertificateExpiry("apps", "web-tls", []string{"a.example.com"}, time.Now())
	metrics.SetCertificateRenewalFailures("apps", "web-tls", 1)
	metrics.ForgetCertificate("apps", "web-tls")
	metrics.SetNetworkRoleResolved("apps", "web", true)
	metrics.ForgetNetworkRole("apps", "web")
}

const (
	certificateExpiry   = "gated_certificate_not_after_timestamp_seconds"
	certificateFailures = "gated_certificate_renewal_failures"
	roleResolved        = "gated_networkrole_target_resolved"
)
