package acme

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/yuanying/gated/internal/certs"
)

func TestChallengeFor(t *testing.T) {
	authz := &xacme.Authorization{
		Identifier: xacme.AuthzID{Type: "dns", Value: "app.example.com"},
		Challenges: []*xacme.Challenge{
			{Type: "tls-alpn-01", Token: "alpn"},
			{Type: "http-01", Token: "http"},
			{Type: "dns-01", Token: "dns"},
		},
	}

	tests := []struct {
		name      string
		want      string
		wantToken string
		wantErr   bool
	}{
		{name: "the solver's own type is chosen", want: ChallengeHTTP01, wantToken: "http"},
		{name: "a type the client does not implement is still selectable", want: ChallengeDNS01, wantToken: "dns"},
		{name: "a type the server does not offer is an error", want: "http-99", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := challengeFor(authz, tc.want)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("challengeFor(%q) = %v, want an error", tc.want, got)
				}
				// The message has to say what was on offer, or a
				// misconfigured solver is undiagnosable.
				if !strings.Contains(err.Error(), "http-01") {
					t.Errorf("the error does not list the offered types: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("challengeFor(%q) = %v", tc.want, err)
			}
			if got.Token != tc.wantToken {
				t.Errorf("token = %q, want %q", got.Token, tc.wantToken)
			}
		})
	}
}

// TestChallengeResponse checks that the value handed to a solver is the one
// its challenge type calls for. This is the only place a second solver has to
// touch, which is what keeps DNS-01 an addition rather than a rewrite.
func TestChallengeResponse(t *testing.T) {
	key, err := newKey()
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	cl := &xacme.Client{Key: key}

	httpResponse, err := challengeResponse(cl, ChallengeHTTP01, "token")
	if err != nil {
		t.Fatalf("challengeResponse(http-01) = %v", err)
	}
	if !strings.HasPrefix(httpResponse, "token.") {
		t.Errorf("the HTTP-01 response %q is not the key authorization", httpResponse)
	}

	dnsResponse, err := challengeResponse(cl, ChallengeDNS01, "token")
	if err != nil {
		t.Fatalf("challengeResponse(dns-01) = %v", err)
	}
	if dnsResponse == httpResponse || dnsResponse == "" {
		t.Errorf("the DNS-01 record %q is not distinct from the HTTP-01 response", dnsResponse)
	}

	if _, err := challengeResponse(cl, "tls-alpn-01", "token"); err == nil {
		t.Error("challengeResponse(tls-alpn-01) = nil, want an error naming the unsupported type")
	}
}

func TestCertificateRequest(t *testing.T) {
	key, err := newKey()
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	der, err := certificateRequest(key, []string{"app.example.com", "api.example.com"})
	if err != nil {
		t.Fatalf("certificateRequest() = %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parsing the request: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("the request is not signed by its own key: %v", err)
	}
	if got, want := csr.DNSNames, []string{"app.example.com", "api.example.com"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("DNSNames = %v, want %v", got, want)
	}
	// A common name would be redundant with the SAN and, at the lengths
	// hostnames reach, is a way to have an order rejected.
	if csr.Subject.CommonName != "" {
		t.Errorf("CommonName = %q, want it left out", csr.Subject.CommonName)
	}
}

// TestEncodeKeypair checks that what the client returns is what a
// kubernetes.io/tls Secret holds, by handing it straight to the renewal
// decision and expecting it to be satisfied.
func TestEncodeKeypair(t *testing.T) {
	key, err := newKey()
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     []string{"app.example.com"},
	}
	leaf, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	issuer := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "issuer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		IsCA:         true,
	}
	intermediate, err := x509.CreateCertificate(rand.Reader, issuer, issuer, key.Public(), key)
	if err != nil {
		t.Fatalf("creating an issuer certificate: %v", err)
	}

	kp, err := encodeKeypair([][]byte{leaf, intermediate}, key)
	if err != nil {
		t.Fatalf("encodeKeypair() = %v", err)
	}

	decision := certs.Evaluate(&certs.Material{CertPEM: kp.CertPEM, KeyPEM: kp.KeyPEM}, []string{"app.example.com"}, time.Now())
	if decision.Renew {
		t.Errorf("the freshly issued keypair is already due for renewal: %s (%s)", decision.Reason, decision.Detail)
	}
	// The chain matters: a client that does not already hold the
	// intermediate cannot build a path without it.
	if got := strings.Count(string(kp.CertPEM), "BEGIN CERTIFICATE"); got != 2 {
		t.Errorf("the PEM holds %d certificates, want the whole chain", got)
	}
}
