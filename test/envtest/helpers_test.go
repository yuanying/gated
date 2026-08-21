//go:build envtest

package envtest_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// intstrFromInt spells a port number in the form the Service API wants.
func intstrFromInt(port int) intstr.IntOrString {
	return intstr.FromInt32(int32(port))
}

// keyOf names an object for a Get.
func keyOf(obj client.Object) types.NamespacedName {
	return types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}
}

// clientHello is the part of a handshake the certificate lookup reads.
func clientHello(serverName string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{ServerName: serverName}
}

// issueSelfSigned returns a certificate for one name, both parsed and in the
// PEM form a kubernetes.io/tls Secret holds.
func issueSelfSigned(t *testing.T, name string) (*tls.Certificate, []byte, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{name},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling the key: %v", err)
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		t.Fatalf("building the keypair: %v", err)
	}
	if cert.Leaf, err = x509.ParseCertificate(der); err != nil {
		t.Fatalf("parsing the certificate: %v", err)
	}
	return &cert, pemCert, pemKey
}
