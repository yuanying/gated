//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"
)

// An Ingress with spec.tls is served over HTTPS with a certificate that was
// obtained for it, and what comes back is the application behind it.
//
// This is the first of the four scenarios, and the one every other scenario
// depends on: without a certificate there is no HTTPS, and gated forwards
// nothing over anything else (ADR 0013).
func TestIngressIsServedWithAnIssuedCertificate(t *testing.T) {
	ctx := testContext(t, settleTimeout)

	chain := certificateFor(t, ctx, "open-tls")
	leaf := chain[0]

	if leaf.Subject.String() == leaf.Issuer.String() {
		t.Fatalf("the certificate is self-signed (%s); nothing was obtained over ACME", leaf.Subject)
	}
	if err := leaf.VerifyHostname(openHost); err != nil {
		t.Fatalf("the certificate is not for %s: %v", openHost, err)
	}

	// Verified against what signed it, so a certificate gated made up for
	// itself would fail the handshake rather than pass the test.
	client := caller(t, issuingRoots(t, chain))

	status, body := get(t, client, https(openHost, "/hello"), nil)
	if status != http.StatusOK {
		t.Fatalf("GET %s answered %d, want 200\n%s", https(openHost, "/hello"), status, body)
	}
	if !fromBackend(body) {
		t.Fatalf("GET %s did not reach the application:\n%s", https(openHost, "/hello"), body)
	}
	if !strings.Contains(body, "path=/hello") {
		t.Fatalf("the application was asked for something other than /hello:\n%s", body)
	}
}

// Nothing is proxied over plain HTTP. The listener that answers port 80 exists
// for ACME challenges and for sending everything else to HTTPS (ADR 0013).
func TestPlainHTTPIsRedirected(t *testing.T) {
	client := caller(t, nil)

	status, _ := get(t, client, "http://"+openHost+"/hello", nil)
	if status != http.StatusPermanentRedirect {
		t.Fatalf("plain HTTP answered %d, want %d", status, http.StatusPermanentRedirect)
	}
}
