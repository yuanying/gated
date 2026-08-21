package proxy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/yuanying/gated/internal/proxy"
	"github.com/yuanying/gated/internal/routing"
)

// selfSigned issues a certificate for the given names. Tests need a real
// keypair because the handshake is part of what is under test.
func selfSigned(t *testing.T, names ...string) *tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              names,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the certificate: %v", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// storeFunc adapts a function to the CertificateStore interface.
type storeFunc func(context.Context, routing.SecretRef) (*tls.Certificate, error)

func (f storeFunc) Certificate(ctx context.Context, ref routing.SecretRef) (*tls.Certificate, error) {
	return f(ctx, ref)
}

// tlsTable holds one Ingress terminating TLS for app.example.com.
func tlsTable() *proxy.TableStore {
	store := &proxy.TableStore{}
	store.Store(routing.BuildTable([]routing.Ingress{{
		Namespace: "apps",
		Name:      "app",
		Rules: []routing.HostRule{{
			Host: "app.example.com",
			Paths: []routing.PathRule{{
				Path:     "/",
				PathType: routing.PathTypePrefix,
				Backend:  routing.Backend{Namespace: "apps", Service: "web", PortNumber: 80},
			}},
		}},
		TLS: []routing.TLSBlock{{Hosts: []string{"app.example.com"}, SecretName: "app-tls"}},
	}}))
	return store
}

func TestGetCertificateUsesSNI(t *testing.T) {
	want := selfSigned(t, "app.example.com")
	var asked routing.SecretRef
	certs := &proxy.Certificates{
		Tables: tlsTable(),
		Store: storeFunc(func(_ context.Context, ref routing.SecretRef) (*tls.Certificate, error) {
			asked = ref
			return want, nil
		}),
	}

	got, err := certs.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate() = _, %v", err)
	}
	if got != want {
		t.Error("GetCertificate() returned a different certificate")
	}
	if wantRef := (routing.SecretRef{Namespace: "apps", Name: "app-tls"}); asked != wantRef {
		t.Errorf("read %+v, want %+v", asked, wantRef)
	}
}

func TestGetCertificateFailsClearlyWhenThereIsNone(t *testing.T) {
	certs := &proxy.Certificates{
		Tables: tlsTable(),
		Store: storeFunc(func(context.Context, routing.SecretRef) (*tls.Certificate, error) {
			t.Error("the store was consulted for a host with no TLS block")
			return nil, nil
		}),
	}

	tests := []struct {
		name       string
		serverName string
	}{
		{"a host nothing terminates TLS for", "other.example.org"},
		{"no SNI at all", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := certs.GetCertificate(&tls.ClientHelloInfo{ServerName: tc.serverName})
			if !errors.Is(err, proxy.ErrNoCertificate) {
				t.Fatalf("GetCertificate() = _, %v, want ErrNoCertificate", err)
			}
		})
	}
}

func TestGetCertificateReportsAStoreFailure(t *testing.T) {
	// A Secret that is named but missing or malformed must not be reported as
	// "no certificate configured": the configuration is right and the state
	// is wrong, and those need different fixes.
	boom := errors.New("the Secret holds no keypair")
	certs := &proxy.Certificates{
		Tables: tlsTable(),
		Store: storeFunc(func(context.Context, routing.SecretRef) (*tls.Certificate, error) {
			return nil, boom
		}),
	}

	_, err := certs.GetCertificate(&tls.ClientHelloInfo{ServerName: "app.example.com"})
	if !errors.Is(err, boom) {
		t.Fatalf("GetCertificate() = _, %v, want the store's error", err)
	}
	if errors.Is(err, proxy.ErrNoCertificate) {
		t.Error("a store failure was reported as a missing configuration")
	}
}

func TestTLSTerminationEndToEnd(t *testing.T) {
	cert := selfSigned(t, "app.example.com")
	certs := &proxy.Certificates{
		Tables: tlsTable(),
		Store: storeFunc(func(context.Context, routing.SecretRef) (*tls.Certificate, error) {
			return cert, nil
		}),
	}

	backend := newEchoServer(t)
	front := newTLSServer(t, certs.TLSConfig(), &proxy.Handler{
		Tables:   tlsTable(),
		Backends: toAddress(backend),
	})

	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
		DialContext:     dialTo(front),
	}}

	resp, err := client.Get("https://app.example.com/")
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	// The backend has to be told the request arrived over TLS, because that
	// is the only way it can tell after termination.
	if got := resp.Header.Get("X-Echo-Forwarded-Proto"); got != "https" {
		t.Errorf("X-Forwarded-Proto seen by the backend = %q, want %q", got, "https")
	}

	// A host with no certificate must fail the handshake rather than be
	// answered with somebody else's certificate.
	if _, err := client.Get("https://other.example.org/"); err == nil {
		t.Error("Get() on a host with no certificate succeeded, want a handshake failure")
	}
}
