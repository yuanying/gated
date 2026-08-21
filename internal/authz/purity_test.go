package authz_test

import (
	"go/build"
	"strings"
	"testing"
)

// TestNoKubernetesImports makes the rule from ADR 0007 executable: the
// authorisation decision takes a subject, a few request attributes and a set
// of permissions, and nothing else. An informer cache or an *http.Request
// reaching in here would put branches of the decision out of reach of a table
// test, and this is the decision whose branches most need enumerating.
//
// The test files are checked as well as the package itself. A test that
// reached for a Kubernetes type would be building its fixtures out of the very
// thing the package is supposed to be independent of.
func TestNoKubernetesImports(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("reading the package: %v", err)
	}

	for _, group := range []struct {
		what    string
		imports []string
	}{
		{"internal/authz", pkg.Imports},
		{"the tests of internal/authz", pkg.TestImports},
		{"the tests of internal/authz", pkg.XTestImports},
	} {
		for _, imported := range group.imports {
			if strings.HasPrefix(imported, "k8s.io/") || strings.HasPrefix(imported, "sigs.k8s.io/") {
				t.Errorf("%s imports %q; the authorisation decision must not depend on Kubernetes", group.what, imported)
			}
			if imported == "net/http" {
				t.Errorf("%s imports %q; the decision takes request attributes, not an HTTP request", group.what, imported)
			}
		}
	}
}
