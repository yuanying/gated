//go:build live

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A certificate is obtained from a real authority, for a name that really
// resolves, and gated serves it.
//
// Everything below the surface of this one scenario is the same code the
// end-to-end suite runs against Pebble. What is not the same is the directory
// answering, and the reason this layer exists is that the two do not answer
// alike: the order is collected one way against Pebble and the other way
// against a real authority, and only one of those two ways is reachable from
// any one run (ADR 0025).
func TestCertificateFromARealAuthority(t *testing.T) {
	if skipReason != "" {
		t.Skip(skipReason)
	}

	ctx := testContext(t, settleTimeout)

	applyObject(t, ctx, liveIngress())

	chain := certificateFor(t, ctx, secretName)
	leaf := chain[0]

	if leaf.Subject.String() == leaf.Issuer.String() {
		t.Fatalf("the certificate is self-signed (%s); nothing was obtained over ACME", leaf.Subject)
	}
	if err := leaf.VerifyHostname(live.host); err != nil {
		t.Fatalf("the certificate is not for the name that was ordered: %v", err)
	}
	t.Logf("issued by %s, valid until %s", leaf.Issuer, leaf.NotAfter.Format("2006-01-02"))

	// Which of the two ways the chain was collected. Against Pebble this is
	// always the order poll, because Pebble's finalize response names no
	// order; a real directory names one, and the ordinary call carries it
	// through. That branch has no other way of being reached.
	via := collectedVia(t, ctx)
	t.Logf("the issued chain was collected via the %s response", via)
	if via != "finalize" {
		t.Fatalf("the chain was collected by polling the order, which is the way round a directory "+
			"that sends no Location header needs; a real directory sends one, so %s reached the "+
			"wrong branch of internal/acme.finalize", live.directory)
	}

	// Verified against what issued it, so a certificate gated made up for
	// itself would fail the handshake rather than pass the test.
	client := caller(t, issuingRoots(t, chain))

	status, body := get(t, client, https(live.host, "/hello"), nil)
	if status != http.StatusOK {
		t.Fatalf("GET /hello answered %d, want 200\n%s", status, body)
	}
	if !fromBackend(body) {
		t.Fatalf("GET /hello did not reach the application:\n%s", body)
	}
}

// liveIngress asks for a certificate for the name this run published, and
// nothing else. No annotation marks it: the TLS block is the instruction
// (ADR 0005).
func liveIngress() *networkingv1.Ingress {
	prefix := networkingv1.PathTypePrefix
	class := "gated"
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: appNamespace, Name: ingressName},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &class,
			TLS: []networkingv1.IngressTLS{{
				Hosts:      []string{live.host},
				SecretName: secretName,
			}},
			Rules: []networkingv1.IngressRule{{
				Host: live.host,
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{
							Path:     "/",
							PathType: &prefix,
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{
									Name: "backend",
									Port: networkingv1.ServiceBackendPort{Number: 8080},
								},
							},
						}},
					},
				},
			}},
		},
	}
}

// collectedVia reads out of gated's log which way the issued chain came back.
//
// The log is where this is visible because it is a property of the exchange
// and not of the certificate: both ways produce the same bytes, and the only
// thing that differs is which call returned them.
func collectedVia(t *testing.T, ctx context.Context) string {
	t.Helper()

	for _, pod := range gatedPods(t, ctx) {
		logs, err := podLogs(ctx, pod.Namespace, pod.Name)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(logs, "\n") {
			if !strings.Contains(line, "obtained a certificate") {
				continue
			}
			if via := field(line, "collectedVia"); via != "" {
				return via
			}
		}
	}
	t.Fatalf("no replica logged obtaining a certificate, so there is nothing to say which way it came back")
	return ""
}

// field pulls one quoted value out of a log line.
func field(line, name string) string {
	marker := fmt.Sprintf("%q:", name)
	i := strings.Index(line, marker)
	if i < 0 {
		return ""
	}
	rest := line[i+len(marker):]
	start := strings.Index(rest, `"`)
	if start < 0 {
		return ""
	}
	rest = rest[start+1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}
