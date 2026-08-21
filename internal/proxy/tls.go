package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/go-logr/logr"

	"github.com/yuanying/gated/internal/routing"
)

// ErrNoCertificate says that nothing in the routing table terminates TLS for
// the name the client asked for. It is a configuration answer, not a failure:
// no Ingress declares that host under spec.tls.
var ErrNoCertificate = errors.New("no certificate is configured for this host")

// CertificateStore returns the keypair held in a Secret.
//
// Certificates live in kubernetes.io/tls Secrets (ADR 0005), which is also how
// they are shared between replicas (ADR 0006). The implementation reads them
// through an informer, so a renewal is picked up without a restart.
type CertificateStore interface {
	Certificate(ctx context.Context, ref routing.SecretRef) (*tls.Certificate, error)
}

// Certificates answers the TLS handshake.
type Certificates struct {
	// Tables says which Secret holds the certificate for a given name.
	Tables *TableStore
	// Store reads and parses that Secret.
	Store CertificateStore
	// Log receives handshakes that could not be answered. The zero Logger
	// discards.
	Log logr.Logger
}

// TLSConfig returns the configuration for the HTTPS listener.
func (c *Certificates) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: c.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		// HTTP/2 for ordinary traffic; a client that wants to upgrade a
		// connection — a WebSocket handshake — negotiates http/1.1 for
		// that connection instead, because upgrades do not exist in h2.
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// GetCertificate picks the certificate for the name in the ClientHello.
//
// A name gated holds no certificate for fails the handshake. Answering with
// somebody else's certificate would turn a missing configuration into a
// browser warning about the wrong subject, which is a much harder thing to
// read back to its cause.
func (c *Certificates) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := routing.CanonicalHost(hello.ServerName)
	if name == "" {
		// Without SNI there is nothing to select on. Every client that
		// matters has sent SNI for a decade.
		c.Log.V(1).Info("TLS handshake without SNI", "remote", remoteAddr(hello))
		return nil, fmt.Errorf("%w: the client sent no server name", ErrNoCertificate)
	}

	ref, ok := c.Tables.Load().Certificate(name)
	if !ok {
		c.Log.V(1).Info("TLS handshake for a host with no certificate", "host", name)
		return nil, fmt.Errorf("%w: %s", ErrNoCertificate, name)
	}

	ctx := hello.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	cert, err := c.Store.Certificate(ctx, ref)
	if err != nil {
		c.Log.Error(err, "reading the certificate", "host", name, "namespace", ref.Namespace, "secret", ref.Name)
		return nil, fmt.Errorf("certificate for %s from %s/%s: %w", name, ref.Namespace, ref.Name, err)
	}
	return cert, nil
}

// remoteAddr reports where a handshake came from, tolerating the synthetic
// ClientHelloInfo values that carry no connection.
func remoteAddr(hello *tls.ClientHelloInfo) string {
	if hello.Conn == nil {
		return ""
	}
	return hello.Conn.RemoteAddr().String()
}
