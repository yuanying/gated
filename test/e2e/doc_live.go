//go:build live

// Package e2e, built with the live tag, orders one certificate from a real
// certificate authority (ADR 0025).
//
// It is the same harness the end-to-end suite runs: the same cluster, the same
// image, the same manifests. Three things are different, and they are the
// three that cannot be different in a cluster that talks to nobody — the
// directory is on the internet rather than in the cluster, the hostname is one
// that really resolves rather than one a test DNS server invents, and the
// address the validation arrives at is the node's own rather than a published
// port.
//
// Nothing here runs unless somebody asks for it. `make verify-live` is the
// only way in, no other target reaches it, and `go test ./...` cannot compile
// it. What it needs — a zone, a token that may edit it, a network carrying
// globally routable addresses, a contact address — comes from the environment
// and has no defaults; without them the run says so and skips.
//
// What it is for is the part of the ACME exchange that Pebble cannot show.
// Pebble's answer to finalize names no order, so the client falls back to
// polling the order it opened; a real directory names one, and the ordinary
// call carries it through instead. Every automated layer takes the first of
// those two branches and only this one takes the second.
package e2e
