//go:build e2e || live

package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// testContext is a context that ends with the test.
func testContext(t *testing.T, timeout time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	return ctx
}

// caller is a client that is not a browser: no cookies, no redirects
// followed. It is what curl and docker look like to gated, and it is the path
// an access token comes in on (ADR 0004).
func caller(t *testing.T, roots *x509.CertPool) *http.Client {
	t.Helper()
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:     dialCluster,
			TLSClientConfig: tlsConfig(roots),
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// tlsConfig verifies gated's certificate against what issued it. Skipping
// verification would make every scenario pass against a certificate that was
// never obtained, which is the thing being tested.
func tlsConfig(roots *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
}

// get makes one request and returns the status and the body.
func get(t *testing.T, c *http.Client, target string, header http.Header) (int, string) {
	t.Helper()
	return request(t, c, http.MethodGet, target, header, nil)
}

func request(t *testing.T, c *http.Client, method, target string, header http.Header, auth *basic) (int, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), method, target, nil)
	if err != nil {
		t.Fatalf("building a request for %s: %v", target, err)
	}
	for name, values := range header {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	if auth != nil {
		req.SetBasicAuth(auth.user, auth.password)
	}

	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("requesting %s: %v", target, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("reading the answer from %s: %v", target, err)
	}
	return resp.StatusCode, string(body)
}

// basic is a user name and a password for BASIC authentication.
type basic struct{ user, password string }

// https builds an address on a host in the test cluster.
func https(host, path string) string {
	return (&url.URL{Scheme: "https", Host: host, Path: path}).String()
}

// certificateFor waits for the certificate an Ingress asked for, and returns
// the chain that was issued.
func certificateFor(t *testing.T, ctx context.Context, secretName string) []*x509.Certificate {
	t.Helper()

	var chain []*x509.Certificate
	key := types.NamespacedName{Namespace: appNamespace, Name: secretName}
	err := poll(ctx, settleTimeout, func(ctx context.Context) (bool, error) {
		var secret corev1.Secret
		if err := k8s.Get(ctx, key, &secret); err != nil {
			return false, nil
		}
		if secret.Type != corev1.SecretTypeTLS {
			return false, nil
		}
		parsed, err := parseChain(secret.Data[corev1.TLSCertKey])
		if err != nil || len(parsed) == 0 {
			return false, nil
		}
		chain = parsed
		return true, nil
	})
	if err != nil {
		t.Fatalf("no certificate was ever written to Secret %s: %v", key, err)
	}
	return chain
}

// parseChain reads a PEM certificate chain.
func parseChain(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no certificate in the data")
	}
	return out, nil
}

// issuingRoots is the pool a test verifies gated's certificates against.
//
// It holds what signed them and not the certificates themselves: an anchor
// taken from the chain above the leaf still fails a certificate that was
// self-signed, or issued for another name, or never issued at all.
func issuingRoots(t *testing.T, chain []*x509.Certificate) *x509.CertPool {
	t.Helper()
	if len(chain) < 2 {
		t.Fatalf("the issued chain has %d certificate(s); nothing above the leaf to trust", len(chain))
	}
	pool := x509.NewCertPool()
	for _, cert := range chain[1:] {
		pool.AddCert(cert)
	}
	return pool
}

// gatedPods lists the running gated replicas.
func gatedPods(t *testing.T, ctx context.Context) []corev1.Pod {
	t.Helper()

	var pods corev1.PodList
	if err := k8s.List(ctx, &pods,
		client.InNamespace(gatedNamespace),
		client.MatchingLabels{"app.kubernetes.io/name": "gated"},
	); err != nil {
		t.Fatalf("listing the gated replicas: %v", err)
	}

	var running []corev1.Pod
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning && p.DeletionTimestamp == nil {
			running = append(running, p)
		}
	}
	return running
}

// podLogs reads a pod's log.
func podLogs(ctx context.Context, namespace, name string) (string, error) {
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return "", err
	}
	stream, err := clientset.CoreV1().Pods(namespace).
		GetLogs(name, &corev1.PodLogOptions{}).Stream(ctx)
	if err != nil {
		return "", err
	}
	defer stream.Close()
	body, err := io.ReadAll(stream)
	return string(body), err
}

// applyObject creates an object and removes it when the test ends, so that a
// role one scenario declares cannot protect another scenario's host.
func applyObject(t *testing.T, ctx context.Context, obj client.Object) {
	t.Helper()
	if err := createOrUpdate(ctx, obj); err != nil {
		t.Fatalf("creating %T %s: %v", obj, client.ObjectKeyFromObject(obj), err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = k8s.Delete(cleanup, obj)
	})
}

// contains reports whether the body came from the application behind the
// Ingress rather than from gated itself.
func fromBackend(body string) bool {
	return strings.Contains(body, "gated-e2e backend")
}
