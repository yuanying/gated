//go:build envtest

package envtest_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/yuanying/gated/internal/controller"
)

// The metric names are the contract with whatever alerts on them (ADR 0031),
// so they are spelled out here rather than reached for through the code.
const (
	certificateExpiry   = "gated_certificate_not_after_timestamp_seconds"
	certificateFailures = "gated_certificate_renewal_failures"
	roleResolved        = "gated_networkrole_target_resolved"
)

// gaugeValue reads one series out of a registry. There is no helper for "the
// value carried by these labels", and asserting on the whole exposition would
// mean knowing an expiry that is minted at run time.
func gaugeValue(t *testing.T, reg prometheus.Gatherer, name string, labels map[string]string) (float64, bool) {
	t.Helper()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gathering: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if !carries(metric, labels) {
				continue
			}
			return metric.GetGauge().GetValue(), true
		}
	}
	return 0, false
}

func carries(metric *dto.Metric, labels map[string]string) bool {
	found := 0
	for _, pair := range metric.GetLabel() {
		want, ok := labels[pair.GetName()]
		if !ok {
			continue
		}
		if pair.GetValue() != want {
			return false
		}
		found++
	}
	return found == len(labels)
}

// meteredCertReconciler is the certificate reconciler with somewhere to report.
func meteredCertReconciler(issuer controller.Issuer, metrics *controller.Metrics) *controller.CertificateReconciler {
	return &controller.CertificateReconciler{
		Client:       k8sClient,
		Reader:       k8sClient,
		IngressClass: ingressClass,
		Issuer:       issuer,
		Recorder:     record.NewFakeRecorder(32),
		Metrics:      metrics,
	}
}

// The expiry is the number an alert counts down from, so it has to be the
// expiry of the certificate that is actually in the Secret.
func TestCertificateExpiryIsReported(t *testing.T) {
	ns := newNamespace(t)
	registry := prometheus.NewPedanticRegistry()
	issuer := &fakeIssuer{notAfter: 90 * 24 * time.Hour}
	r := meteredCertReconciler(issuer, controller.NewMetrics(registry))

	const host = "metrics.certs.example.com"
	ing := tlsIngress(t, ns, "app", "app-tls", host)
	if err := reconcileIngress(t, r, ing); err != nil {
		t.Fatalf("Reconcile() = %v", err)
	}

	secret := map[string]string{"namespace": ns, "secret": "app-tls"}
	covering := map[string]string{"namespace": ns, "secret": "app-tls", "host": host}
	got, ok := gaugeValue(t, registry, certificateExpiry, covering)
	if !ok {
		t.Fatalf("%s carries no series for %v", certificateExpiry, covering)
	}
	want := float64(time.Now().Add(90 * 24 * time.Hour).Unix())
	if diff := got - want; diff > 60 || diff < -60 {
		t.Errorf("%s = %v, want the expiry of the issued certificate, about %v", certificateExpiry, got, want)
	}

	if failures, ok := gaugeValue(t, registry, certificateFailures, secret); !ok || failures != 0 {
		t.Errorf("%s = %v (present: %v), want 0 after an issuance that worked", certificateFailures, failures, ok)
	}
}

// A renewal that keeps failing is the state ADR 0014 makes deliberately quiet:
// the certificate in place is kept and nothing breaks until it expires. The
// count is what makes the quiet visible.
func TestConsecutiveRenewalFailuresAreReported(t *testing.T) {
	ns := newNamespace(t)
	registry := prometheus.NewPedanticRegistry()
	issuer := &fakeIssuer{err: errors.New("the directory is unreachable")}
	r := meteredCertReconciler(issuer, controller.NewMetrics(registry))

	const host = "failing.certs.example.com"
	ing := tlsIngress(t, ns, "app", "app-tls", host)
	for attempt := 1; attempt <= 3; attempt++ {
		if err := reconcileIngress(t, r, ing); err == nil {
			t.Fatalf("attempt %d: Reconcile() = nil, want the issuance failure", attempt)
		}
	}

	labels := map[string]string{"namespace": ns, "secret": "app-tls"}
	if got, ok := gaugeValue(t, registry, certificateFailures, labels); !ok || got != 3 {
		t.Errorf("%s = %v (present: %v), want 3", certificateFailures, got, ok)
	}
	// Nothing was ever issued, so there is no expiry to count down to.
	if _, ok := gaugeValue(t, registry, certificateExpiry, labels); ok {
		t.Errorf("%s carries a series for a Secret that holds nothing usable", certificateExpiry)
	}
}

// A gauge nobody removes goes on reporting an expiry that is nobody's job any
// more, and eventually alerts about a certificate that is not being renewed
// because it is not wanted.
func TestCertificateMetricsGoWhenTheIngressDoes(t *testing.T) {
	ns := newNamespace(t)
	registry := prometheus.NewPedanticRegistry()
	r := meteredCertReconciler(&fakeIssuer{}, controller.NewMetrics(registry))

	ing := tlsIngress(t, ns, "app", "app-tls", "departing.certs.example.com")
	if err := reconcileIngress(t, r, ing); err != nil {
		t.Fatalf("Reconcile() = %v", err)
	}
	if got := testutil.CollectAndCount(registry, certificateExpiry); got != 1 {
		t.Fatalf("%s has %d series, want 1", certificateExpiry, got)
	}

	if err := k8sClient.Delete(context.Background(), ing); err != nil {
		t.Fatalf("deleting the Ingress: %v", err)
	}
	if err := reconcileIngress(t, r, ing); err != nil {
		t.Fatalf("Reconcile() after the delete = %v", err)
	}

	if got := testutil.CollectAndCount(registry, certificateExpiry); got != 0 {
		t.Errorf("%s has %d series after the Ingress went away, want none", certificateExpiry, got)
	}
	if got := testutil.CollectAndCount(registry, certificateFailures); got != 0 {
		t.Errorf("%s has %d series after the Ingress went away, want none", certificateFailures, got)
	}
}

// The whole point of the series: a role that resolves to nothing protects
// nothing, and what it meant to protect is served to everybody (ADR 0002).
func TestNetworkRoleResolutionIsReported(t *testing.T) {
	ns := newNamespace(t)
	registry := prometheus.NewPedanticRegistry()
	r := &controller.NetworkRoleReconciler{
		Client:   k8sClient,
		Reader:   k8sClient,
		Recorder: record.NewFakeRecorder(32),
		Metrics:  controller.NewMetrics(registry),
	}

	newProtectedIngress(t, ns, "storefront", "roles.metrics.example.com")
	resolved := newNetworkRole(t, ns, "resolved", "storefront", rule([]string{"*"}, "GET"))
	broken := newNetworkRole(t, ns, "broken", "misspelled", rule([]string{"*"}, "GET"))

	for _, role := range []string{resolved.Name, broken.Name} {
		if _, err := r.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{Namespace: ns, Name: role},
		}); err != nil {
			t.Fatalf("Reconcile(%s) = %v", role, err)
		}
	}

	if got, ok := gaugeValue(t, registry, roleResolved, map[string]string{"namespace": ns, "name": resolved.Name}); !ok || got != 1 {
		t.Errorf("%s for the resolved role = %v (present: %v), want 1", roleResolved, got, ok)
	}
	if got, ok := gaugeValue(t, registry, roleResolved, map[string]string{"namespace": ns, "name": broken.Name}); !ok || got != 0 {
		t.Errorf("%s for the unresolved role = %v (present: %v), want 0", roleResolved, got, ok)
	}

	// A role that has been deleted is not an unresolved role, and leaving
	// the zero behind would alert about a hole nobody has.
	if err := k8sClient.Delete(context.Background(), broken); err != nil {
		t.Fatalf("deleting the NetworkRole: %v", err)
	}
	if _, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: broken.Name},
	}); err != nil {
		t.Fatalf("Reconcile() after the delete = %v", err)
	}
	if _, ok := gaugeValue(t, registry, roleResolved, map[string]string{"namespace": ns, "name": broken.Name}); ok {
		t.Errorf("%s still carries a series for a role that is gone", roleResolved)
	}
}
