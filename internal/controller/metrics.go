package controller

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics are the series a reconciler publishes about what it found (ADR 0031).
//
// They come from the leader alone, because the reconcilers that fill them run
// under the lease (ADR 0006). A replica that never wins it reports none of
// them, which is not a gap: it is a process saying nothing about work it does
// not do. Anything reading these has to take them across replicas rather than
// from one.
//
// Every method is safe on a nil *Metrics, so that a reconciler can be built
// without one.
type Metrics struct {
	certificateNotAfter        *prometheus.GaugeVec
	certificateRenewalFailures *prometheus.GaugeVec
	networkRoleTargetResolved  *prometheus.GaugeVec
}

// certificateLabels name the Secret a certificate lives in. The host is added
// to the expiry alone: a certificate is issued for hosts, and the number is
// read to find out when a host stops being served.
var certificateLabels = []string{"namespace", "secret"}

// NewMetrics registers the reconcilers' metrics with reg and returns them.
//
// It panics if they are already registered, which is what registering the same
// collector twice in one process means.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		certificateNotAfter: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "gated_certificate_not_after_timestamp_seconds",
			Help: "When the certificate in place expires, as a Unix timestamp.",
		}, append(append([]string{}, certificateLabels...), "host")),
		certificateRenewalFailures: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "gated_certificate_renewal_failures",
			Help: "Consecutive failures to obtain the certificate for this Secret.",
		}, certificateLabels),
		networkRoleTargetResolved: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "gated_networkrole_target_resolved",
			Help: "Whether this NetworkRole's targetRef names something gated could find.",
		}, []string{"namespace", "name"}),
	}
	reg.MustRegister(m.certificateNotAfter, m.certificateRenewalFailures, m.networkRoleTargetResolved)
	return m
}

// SetCertificateExpiry reports when the certificate in a Secret runs out, for
// each host it covers.
//
// Hosts that were reported before and are not named now are dropped: a host
// taken off a certificate has no expiry, and the number left behind would go
// on counting down towards an alert about a certificate nobody is renewing.
func (m *Metrics) SetCertificateExpiry(namespace, secret string, hosts []string, notAfter time.Time) {
	if m == nil {
		return
	}
	m.certificateNotAfter.DeletePartialMatch(prometheus.Labels{"namespace": namespace, "secret": secret})
	for _, host := range hosts {
		m.certificateNotAfter.WithLabelValues(namespace, secret, host).Set(float64(notAfter.Unix()))
	}
}

// SetCertificateRenewalFailures reports how many attempts in a row have failed.
//
// Zero is reported rather than nothing at all. A series that vanishes on
// success cannot be told from one whose process has died.
func (m *Metrics) SetCertificateRenewalFailures(namespace, secret string, failures int) {
	if m == nil {
		return
	}
	m.certificateRenewalFailures.WithLabelValues(namespace, secret).Set(float64(failures))
}

// ForgetCertificate drops everything reported about one Secret, for when there
// is no longer anything to report it about.
func (m *Metrics) ForgetCertificate(namespace, secret string) {
	if m == nil {
		return
	}
	labels := prometheus.Labels{"namespace": namespace, "secret": secret}
	m.certificateNotAfter.DeletePartialMatch(labels)
	m.certificateRenewalFailures.DeletePartialMatch(labels)
}

// SetNetworkRoleResolved reports whether a role's targetRef named something
// that could be found.
//
// This is the one number that makes the hole ADR 0002 accepted visible: a role
// that resolves to nothing protects nothing, and what it meant to protect is
// served to everybody without a word of complaint anywhere else.
func (m *Metrics) SetNetworkRoleResolved(namespace, name string, resolved bool) {
	if m == nil {
		return
	}
	value := 0.0
	if resolved {
		value = 1
	}
	m.networkRoleTargetResolved.WithLabelValues(namespace, name).Set(value)
}

// ForgetNetworkRole drops what was reported about a role that is gone. A role
// that no longer exists is not an unresolved one.
func (m *Metrics) ForgetNetworkRole(namespace, name string) {
	if m == nil {
		return
	}
	m.networkRoleTargetResolved.DeleteLabelValues(namespace, name)
}
