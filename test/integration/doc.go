//go:build integration

// Package integration holds the tests that need a local Pebble instance and a
// fake identity provider (ADR 0007). They are kept behind the integration
// build tag so that `go test ./...` stays free of external dependencies.
//
// The tests themselves arrive with the ACME client and the connectors.
package integration
