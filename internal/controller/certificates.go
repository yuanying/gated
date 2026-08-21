package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/yuanying/gated/internal/routing"
)

// SecretCertificates reads certificates out of kubernetes.io/tls Secrets.
//
// The read goes through the informer cache, so a renewal written by the leader
// (ADR 0006) is picked up on the next handshake without a restart. Parsing is
// what costs, so the parsed keypair is kept and reused until the Secret's
// resource version changes.
type SecretCertificates struct {
	// Reader reads Secrets, from the manager's cache.
	Reader client.Reader

	mu     sync.RWMutex
	parsed map[routing.SecretRef]parsedCertificate
}

type parsedCertificate struct {
	resourceVersion string
	cert            *tls.Certificate
}

// Certificate returns the keypair held in a Secret.
func (c *SecretCertificates) Certificate(ctx context.Context, ref routing.SecretRef) (*tls.Certificate, error) {
	var secret corev1.Secret
	key := types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}
	if err := c.Reader.Get(ctx, key, &secret); err != nil {
		return nil, fmt.Errorf("reading Secret %s: %w", key, err)
	}
	if secret.Type != corev1.SecretTypeTLS {
		return nil, fmt.Errorf("Secret %s is of type %q, want %q", key, secret.Type, corev1.SecretTypeTLS)
	}

	if cert, ok := c.cached(ref, secret.ResourceVersion); ok {
		return cert, nil
	}

	cert, err := tls.X509KeyPair(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return nil, fmt.Errorf("Secret %s does not hold a usable keypair: %w", key, err)
	}
	// X509KeyPair leaves Leaf unset. Filling it in here means the handshake
	// does not reparse the certificate, and lets the renewal decision read
	// the validity dates without touching the Secret again.
	if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
		cert.Leaf = leaf
	}

	c.store(ref, secret.ResourceVersion, &cert)
	return &cert, nil
}

func (c *SecretCertificates) cached(ref routing.SecretRef, resourceVersion string) (*tls.Certificate, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.parsed[ref]
	if !ok || entry.resourceVersion != resourceVersion {
		return nil, false
	}
	return entry.cert, true
}

func (c *SecretCertificates) store(ref routing.SecretRef, resourceVersion string, cert *tls.Certificate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.parsed == nil {
		c.parsed = map[routing.SecretRef]parsedCertificate{}
	}
	c.parsed[ref] = parsedCertificate{resourceVersion: resourceVersion, cert: cert}
}
