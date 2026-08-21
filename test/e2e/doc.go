//go:build e2e

// Package e2e holds the end-to-end tests that run against a kind cluster with
// Pebble and a mock identity provider alongside (ADR 0007). They are kept
// behind the e2e build tag, and cover the four scenarios of the goal rather
// than the full matrix; exhaustiveness belongs to the pure unit tests.
//
// The tests themselves arrive once the proxy and the controllers do.
package e2e
