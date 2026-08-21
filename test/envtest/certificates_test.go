//go:build envtest

package envtest_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	gatedacme "github.com/yuanying/gated/internal/acme"
	"github.com/yuanying/gated/internal/controller"
)

// fakeIssuer stands in for the ACME directory. Talking to a real one is the
// integration suite's job (ADR 0007); what is under test here is what the
// reconciler does with the answer, including when there is none.
type fakeIssuer struct {
	calls    int
	hosts    [][]string
	err      error
	notAfter time.Duration
}

func (f *fakeIssuer) Obtain(_ context.Context, hosts []string) (*gatedacme.Keypair, error) {
	f.calls++
	f.hosts = append(f.hosts, append([]string(nil), hosts...))
	if f.err != nil {
		return nil, f.err
	}
	validity := f.notAfter
	if validity == 0 {
		validity = 90 * 24 * time.Hour
	}
	certPEM, keyPEM := mintCert(nil, time.Now().Add(validity), hosts...)
	return &gatedacme.Keypair{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// mintCert makes a self-signed certificate expiring at notAfter, in the PEM a
// kubernetes.io/tls Secret holds. A nil *testing.T means a caller that cannot
// fail the test, which is why the errors panic.
func mintCert(t *testing.T, notAfter time.Time, hosts ...string) ([]byte, []byte) {
	if t != nil {
		t.Helper()
	}
	fail := func(err error) {
		if t != nil {
			t.Fatalf("minting a certificate: %v", err)
		}
		panic(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fail(err)
	}
	// A ninety day window puts the renewal threshold thirty days out,
	// which is the shape the tests reason about.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     hosts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		fail(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fail(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// certReconciler wires the reconciler against the test control plane.
func certReconciler(t *testing.T, issuer controller.Issuer) (*controller.CertificateReconciler, *record.FakeRecorder) {
	t.Helper()

	events := record.NewFakeRecorder(32)
	return &controller.CertificateReconciler{
		Client:       k8sClient,
		Reader:       k8sClient,
		IngressClass: "gated",
		Issuer:       issuer,
		Recorder:     events,
	}, events
}

// tlsIngress creates an Ingress that terminates TLS for hosts.
func tlsIngress(t *testing.T, ns, name, secretName string, hosts ...string) *networkingv1.Ingress {
	t.Helper()

	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To("gated"),
			TLS:              []networkingv1.IngressTLS{{Hosts: hosts, SecretName: secretName}},
			Rules: []networkingv1.IngressRule{{
				Host: hosts[0],
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{
							Path:     "/",
							PathType: ptr.To(networkingv1.PathTypePrefix),
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{
									Name: "backend",
									Port: networkingv1.ServiceBackendPort{Number: 80},
								},
							},
						}},
					},
				},
			}},
		},
	}
	if err := k8sClient.Create(context.Background(), ing); err != nil {
		t.Fatalf("creating the Ingress: %v", err)
	}
	// Namespaces are not collected in envtest — there is no controller
	// manager behind them — so an Ingress left here goes on being listed
	// by every other suite that builds a routing table.
	t.Cleanup(func() {
		if err := k8sClient.Delete(context.Background(), ing); err != nil {
			t.Logf("deleting the Ingress: %v", err)
		}
	})
	return ing
}

// putTLSSecret places a certificate where an Ingress expects to find one.
func putTLSSecret(t *testing.T, ns, name string, certPEM, keyPEM []byte) *corev1.Secret {
	t.Helper()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{corev1.TLSCertKey: certPEM, corev1.TLSPrivateKeyKey: keyPEM},
	}
	if err := k8sClient.Create(context.Background(), secret); err != nil {
		t.Fatalf("creating the Secret: %v", err)
	}
	t.Cleanup(func() {
		if err := k8sClient.Delete(context.Background(), secret); err != nil {
			t.Logf("deleting the Secret: %v", err)
		}
	})
	return secret
}

func getSecret(t *testing.T, ns, name string) *corev1.Secret {
	t.Helper()

	var secret corev1.Secret
	if err := k8sClient.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &secret); err != nil {
		t.Fatalf("reading Secret %s/%s: %v", ns, name, err)
	}
	return &secret
}

func reconcileIngress(t *testing.T, r *controller.CertificateReconciler, ing *networkingv1.Ingress) error {
	t.Helper()

	_, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{
		Namespace: ing.Namespace, Name: ing.Name,
	}})
	return err
}

// drain collects the events recorded so far.
func drain(events *record.FakeRecorder) []string {
	var out []string
	for {
		select {
		case e := <-events.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

func containing(events []string, substr string) bool {
	for _, e := range events {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}

// TestCertificateIsIssuedFromSpecTLS is the trigger ADR 0005 chose: spec.tls
// on its own, with no annotation to remember.
func TestCertificateIsIssuedFromSpecTLS(t *testing.T) {
	ns := newNamespace(t)
	issuer := &fakeIssuer{}
	r, events := certReconciler(t, issuer)

	ing := tlsIngress(t, ns, "app", "app-tls", "one.certs.example.com", "two.certs.example.com")
	if err := reconcileIngress(t, r, ing); err != nil {
		t.Fatalf("Reconcile() = %v", err)
	}

	if issuer.calls != 1 {
		t.Fatalf("the issuer was called %d times, want 1", issuer.calls)
	}
	if got := issuer.hosts[0]; len(got) != 2 || got[0] != "one.certs.example.com" || got[1] != "two.certs.example.com" {
		t.Errorf("ordered for %v, want both hosts of the tls block", got)
	}

	secret := getSecret(t, ns, "app-tls")
	if secret.Type != corev1.SecretTypeTLS {
		t.Errorf("Secret type = %q, want %q", secret.Type, corev1.SecretTypeTLS)
	}
	if len(secret.Data[corev1.TLSCertKey]) == 0 || len(secret.Data[corev1.TLSPrivateKeyKey]) == 0 {
		t.Errorf("the Secret does not hold a keypair: %v", secret.Data)
	}
	if !containing(drain(events), "Issued") {
		t.Error("no event records the issuance")
	}
}

// TestExistingCertificateIsLeftAlone covers the promise ADR 0005 makes to a
// certificate somebody put there by hand.
func TestExistingCertificateIsLeftAlone(t *testing.T) {
	ns := newNamespace(t)
	issuer := &fakeIssuer{}
	r, _ := certReconciler(t, issuer)

	certPEM, keyPEM := mintCert(t, time.Now().Add(80*24*time.Hour), "kept.certs.example.com")
	putTLSSecret(t, ns, "app-tls", certPEM, keyPEM)

	ing := tlsIngress(t, ns, "app", "app-tls", "kept.certs.example.com")
	if err := reconcileIngress(t, r, ing); err != nil {
		t.Fatalf("Reconcile() = %v", err)
	}

	if issuer.calls != 0 {
		t.Errorf("the issuer was called %d times for a Secret that already holds a valid certificate", issuer.calls)
	}
	if got := getSecret(t, ns, "app-tls"); string(got.Data[corev1.TLSCertKey]) != string(certPEM) {
		t.Error("the existing certificate was replaced")
	}
}

// TestFailedRenewalKeepsTheExistingCertificate is the requirement ADR 0005
// calls mandatory: a renewal that cannot be completed must not cost the host
// the certificate it still has.
func TestFailedRenewalKeepsTheExistingCertificate(t *testing.T) {
	ns := newNamespace(t)
	issuer := &fakeIssuer{err: errors.New("the directory is unreachable")}
	r, events := certReconciler(t, issuer)

	// Five days left: inside the thirty day renewal window, and still
	// perfectly serviceable.
	certPEM, keyPEM := mintCert(t, time.Now().Add(5*24*time.Hour), "failed.certs.example.com")
	putTLSSecret(t, ns, "app-tls", certPEM, keyPEM)

	ing := tlsIngress(t, ns, "app", "app-tls", "failed.certs.example.com")
	for attempt := 1; attempt <= 3; attempt++ {
		if err := reconcileIngress(t, r, ing); err == nil {
			t.Fatalf("attempt %d: Reconcile() = nil, want the issuance failure so the queue backs off", attempt)
		}
	}

	if issuer.calls != 3 {
		t.Errorf("the issuer was called %d times, want one per reconcile", issuer.calls)
	}
	secret := getSecret(t, ns, "app-tls")
	if string(secret.Data[corev1.TLSCertKey]) != string(certPEM) {
		t.Error("the certificate in place was replaced or removed by a failed renewal")
	}
	if string(secret.Data[corev1.TLSPrivateKeyKey]) != string(keyPEM) {
		t.Error("the private key in place was replaced or removed by a failed renewal")
	}

	recorded := drain(events)
	if !containing(recorded, "the directory is unreachable") {
		t.Errorf("no event carries the reason: %v", recorded)
	}
	// ADR 0005 asks for the number of attempts as well as the reason.
	if !containing(recorded, "attempt 3") {
		t.Errorf("no event carries the attempt count: %v", recorded)
	}
}

// TestExpiringCertificateIsRenewed is the other half: when the order does
// succeed, the new certificate lands.
func TestExpiringCertificateIsRenewed(t *testing.T) {
	ns := newNamespace(t)
	issuer := &fakeIssuer{}
	r, _ := certReconciler(t, issuer)

	certPEM, keyPEM := mintCert(t, time.Now().Add(5*24*time.Hour), "renewed.certs.example.com")
	putTLSSecret(t, ns, "app-tls", certPEM, keyPEM)

	ing := tlsIngress(t, ns, "app", "app-tls", "renewed.certs.example.com")
	if err := reconcileIngress(t, r, ing); err != nil {
		t.Fatalf("Reconcile() = %v", err)
	}
	if issuer.calls != 1 {
		t.Fatalf("the issuer was called %d times, want 1", issuer.calls)
	}
	if got := getSecret(t, ns, "app-tls"); string(got.Data[corev1.TLSCertKey]) == string(certPEM) {
		t.Error("the expiring certificate was not replaced")
	}
}

// TestHostAddedToSpecTLSIsOrdered covers the Ingress growing a host: the
// certificate in place no longer covers everything it has to.
func TestHostAddedToSpecTLSIsOrdered(t *testing.T) {
	ns := newNamespace(t)
	issuer := &fakeIssuer{}
	r, _ := certReconciler(t, issuer)

	certPEM, keyPEM := mintCert(t, time.Now().Add(80*24*time.Hour), "grown.certs.example.com")
	putTLSSecret(t, ns, "app-tls", certPEM, keyPEM)

	ing := tlsIngress(t, ns, "app", "app-tls", "grown.certs.example.com", "extra.certs.example.com")
	if err := reconcileIngress(t, r, ing); err != nil {
		t.Fatalf("Reconcile() = %v", err)
	}
	if issuer.calls != 1 {
		t.Errorf("the issuer was called %d times for a certificate missing a host, want 1", issuer.calls)
	}
}

// TestAnotherControllersIngressIsIgnored keeps gated from spending an issuance
// rate limit on traffic it does not serve.
func TestAnotherControllersIngressIsIgnored(t *testing.T) {
	ns := newNamespace(t)
	issuer := &fakeIssuer{}
	r, _ := certReconciler(t, issuer)

	ing := tlsIngress(t, ns, "app", "app-tls", "other.certs.example.com")
	ing.Spec.IngressClassName = ptr.To("somebody-else")
	if err := k8sClient.Update(context.Background(), ing); err != nil {
		t.Fatalf("updating the Ingress: %v", err)
	}

	if err := reconcileIngress(t, r, ing); err != nil {
		t.Fatalf("Reconcile() = %v", err)
	}
	if issuer.calls != 0 {
		t.Errorf("the issuer was called %d times for another controller's Ingress", issuer.calls)
	}
}

// TestReconcileSchedulesTheNextLook checks that a certificate nobody touches
// still gets renewed: the result carries the requeue that brings the
// reconciler back before the renewal window opens.
func TestReconcileSchedulesTheNextLook(t *testing.T) {
	ns := newNamespace(t)
	issuer := &fakeIssuer{}
	r, _ := certReconciler(t, issuer)

	certPEM, keyPEM := mintCert(t, time.Now().Add(80*24*time.Hour), "scheduled.certs.example.com")
	putTLSSecret(t, ns, "app-tls", certPEM, keyPEM)
	ing := tlsIngress(t, ns, "app", "app-tls", "scheduled.certs.example.com")

	result, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{
		Namespace: ing.Namespace, Name: ing.Name,
	}})
	if err != nil {
		t.Fatalf("Reconcile() = %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Error("the reconciler scheduled no further look; a certificate nobody touches would expire")
	}
}
