//go:build e2e

// Package e2e runs gated in a kind cluster, with the ACME test server and a
// stand-in identity provider alongside it, and checks the four things the
// whole design exists to do (ADR 0007):
//
//   - an Ingress with spec.tls gets a certificate and is served over HTTPS
//   - a NetworkRole sends an anonymous visitor to log in, and the subject they
//     come back as decides whether they get through
//   - an AccessToken is accepted as a bearer credential and in the password
//     field of BASIC authentication
//   - several replicas issue one certificate between them, and any of them can
//     answer an ACME challenge
//
// Everything else is somebody else's job. Whether a particular path pattern
// matches, whether a particular subject is allowed, whether a certificate is
// due for renewal — those are pure functions with table tests, and repeating
// them here would cost minutes to learn nothing. What only this layer can find
// is the seam: a pure function that is right, wired to an input that is not.
//
// Nothing here contacts a real certificate authority or a real identity
// provider. Both are in the cluster and go away with it.
package e2e
