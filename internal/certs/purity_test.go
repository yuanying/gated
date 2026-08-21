package certs_test

import (
	"go/build"
	"strings"
	"testing"
)

// TestNoKubernetesImports makes the rule from ADR 0007 executable: the renewal
// decision is a pure function of a certificate, a set of hosts and a clock, and
// stays reachable from a table test without an API server. Reaching for a
// Kubernetes type here is how that erodes, so the package's own import list is
// the place to catch it.
func TestNoKubernetesImports(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("reading the package: %v", err)
	}

	for _, imported := range pkg.Imports {
		if strings.HasPrefix(imported, "k8s.io/") || strings.HasPrefix(imported, "sigs.k8s.io/") {
			t.Errorf("internal/certs imports %q; the renewal decision must not depend on Kubernetes", imported)
		}
	}
}
