//go:build integration

// Package integration holds the tests that need a local Pebble instance and a
// fake identity provider (ADR 0007). They are kept behind the integration
// build tag so that `go test ./...` stays free of external dependencies.
//
// The ACME tests start Pebble and its challenge DNS server as containers on
// the host network, so that the CA can reach the plain listener gated answers
// challenges on. Nothing here contacts a real directory.
package integration
