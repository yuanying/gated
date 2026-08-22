package routing_test

import (
	"net/url"
	"testing"

	"github.com/yuanying/gated/internal/routing"
)

// TestCheckPath enumerates the shapes a request line can take and says, for
// each, whether gated is willing to route it (ADR 0012).
//
// The cases are written as the target of a request line rather than as a
// decoded path, and parsed the way net/http parses one, so that the pair the
// check reads — the decoded path and the escaped form it came from — is the
// pair a request would actually carry.
func TestCheckPath(t *testing.T) {
	tests := []struct {
		name   string
		target string
		reject bool
	}{
		// The traversal itself, in the spellings that reach the same
		// place. Each of these is a path a string-prefix authorisation
		// rule cannot see through (ADR 0017).
		{"a dot-dot segment", "/allowed/../secret", true},
		{"a dot-dot segment, percent-encoded", "/allowed/%2e%2e/secret", true},
		{"a dot-dot segment, percent-encoded in upper case", "/allowed/%2E%2E/secret", true},
		{"a dot-dot segment carrying a path parameter", "/allowed/..;/secret", true},
		{"a dot-dot segment with a named parameter", "/allowed/..;a=b/secret", true},
		{"a single-dot segment", "/allowed/./secret", true},
		{"a single-dot segment carrying a path parameter", "/allowed/.;/secret", true},
		{"a trailing dot-dot segment", "/allowed/..", true},
		{"a leading dot-dot segment", "/../secret", true},
		{"the path is nothing but a dot-dot segment", "/..", true},
		{"an encoded slash", "/allowed%2Fsecret", true},
		{"an encoded slash in lower case", "/allowed%2fsecret", true},
		{"an encoded dot, harmless on its own", "/allowed/%2e/secret", true},
		{"an encoded dot in a segment that means nothing else", "/a%2Eb", true},

		// Everything below is a path somebody's application really
		// serves. Refusing any of these would be gated breaking a
		// working route in the name of a traversal that is not there.
		{"a plain path", "/a/b", false},
		{"a trailing slash", "/a/b/", false},
		{"the root", "/", false},
		{"an empty segment", "//a", false},
		{"an empty segment in the middle", "/a//b", false},
		{"a space, percent-encoded", "/a%20b", false},
		{"a path parameter", "/a;jsessionid=x", false},
		{"a path parameter on the last segment", "/a/b;v=1", false},
		{"a segment that merely starts with dots", "/..a/b", false},
		{"a segment that merely ends with dots", "/a../b", false},
		{"a dot inside a segment", "/a.b/c", false},
		{"a file extension", "/static/app.min.js", false},
		{"a percent-encoded character above ASCII", "/%E3%81%82", false},
		{"a query string is not part of the path", "/a/b?x=../y", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.ParseRequestURI(tc.target)
			if err != nil {
				t.Fatalf("ParseRequestURI(%q) = %v", tc.target, err)
			}
			err = routing.CheckPath(u.Path, u.RawPath)
			if tc.reject && err == nil {
				t.Errorf("CheckPath(%q) = nil, want a refusal", tc.target)
			}
			if !tc.reject && err != nil {
				t.Errorf("CheckPath(%q) = %v, want it accepted", tc.target, err)
			}
		})
	}
}

// TestCheckPathAcceptsWhatIsNotAPath keeps the check total: a request line can
// carry a target that is not a path at all, and the check has to answer for it
// rather than assume a leading slash.
func TestCheckPathAcceptsWhatIsNotAPath(t *testing.T) {
	for _, p := range []string{"", "*"} {
		if err := routing.CheckPath(p, ""); err != nil {
			t.Errorf("CheckPath(%q) = %v, want it accepted", p, err)
		}
	}
}
