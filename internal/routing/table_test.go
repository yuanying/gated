package routing_test

import (
	"testing"
	"time"

	"github.com/yuanying/gated/internal/routing"
)

// backend is a shorthand for the destinations the tables below point at. The
// tests only ever compare them for equality, so the fields carry no meaning
// beyond being distinct.
func backend(name string) routing.Backend {
	return routing.Backend{Namespace: "apps", Service: name, PortNumber: 80}
}

// ingress builds a single-host Ingress out of path/backend pairs.
func ingress(name, host string, paths ...routing.PathRule) routing.Ingress {
	return routing.Ingress{
		Namespace: "apps",
		Name:      name,
		Rules:     []routing.HostRule{{Host: host, Paths: paths}},
	}
}

func path(p string, t routing.PathType, b routing.Backend) routing.PathRule {
	return routing.PathRule{Path: p, PathType: t, Backend: b}
}

func TestMatchHostPrecedence(t *testing.T) {
	// Three tiers claim the same path. Which one answers is the whole point
	// of the test: exact wins over wildcard, wildcard over the host-less
	// catch-all.
	table := routing.BuildTable([]routing.Ingress{
		ingress("exact", "app.example.com", path("/", routing.PathTypePrefix, backend("exact"))),
		ingress("wildcard", "*.example.com", path("/", routing.PathTypePrefix, backend("wildcard"))),
		ingress("catchall", "", path("/", routing.PathTypePrefix, backend("catchall"))),
	})

	tests := []struct {
		name string
		host string
		want string
	}{
		{"exact host wins", "app.example.com", "exact"},
		{"wildcard covers a sibling label", "other.example.com", "wildcard"},
		{"wildcard does not cover the bare domain", "example.com", "catchall"},
		{"wildcard covers exactly one label", "a.b.example.com", "catchall"},
		{"an unclaimed host falls through to the catch-all", "elsewhere.example.org", "catchall"},
		{"the host is matched case-insensitively", "APP.Example.COM", "exact"},
		{"the port is not part of the host", "app.example.com:8443", "exact"},
		{"a trailing dot is not part of the host", "app.example.com.", "exact"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := table.Match(tc.host, "/")
			if !ok {
				t.Fatalf("Match(%q, %q) = _, false, want a match", tc.host, "/")
			}
			if got.Backend.Service != tc.want {
				t.Errorf("Match(%q, %q).Backend.Service = %q, want %q", tc.host, "/", got.Backend.Service, tc.want)
			}
		})
	}
}

func TestMatchFallsThroughWhenNoPathMatches(t *testing.T) {
	// The exact host owns /admin only. A request for anything else on that
	// host is not a 404 for the whole host: the wildcard tier still gets to
	// answer, the same way a more specific route failing to match hands the
	// request back to the general one.
	table := routing.BuildTable([]routing.Ingress{
		ingress("exact", "app.example.com", path("/admin", routing.PathTypePrefix, backend("admin"))),
		ingress("wildcard", "*.example.com", path("/", routing.PathTypePrefix, backend("wildcard"))),
	})

	got, ok := table.Match("app.example.com", "/public")
	if !ok {
		t.Fatalf("Match() = _, false, want a match")
	}
	if got.Backend.Service != "wildcard" {
		t.Errorf("Backend.Service = %q, want %q", got.Backend.Service, "wildcard")
	}
}

func TestMatchPathPrecedence(t *testing.T) {
	table := routing.BuildTable([]routing.Ingress{
		ingress("app", "app.example.com",
			path("/", routing.PathTypePrefix, backend("root")),
			path("/api", routing.PathTypePrefix, backend("api")),
			path("/api/v2", routing.PathTypePrefix, backend("api-v2")),
			path("/api/v2/health", routing.PathTypeExact, backend("health")),
			path("/legacy", routing.PathTypeImplementationSpecific, backend("legacy")),
		),
	})

	tests := []struct {
		name string
		path string
		want string
	}{
		{"the root prefix catches what nothing else claims", "/", "root"},
		{"the root prefix catches a deep path", "/nothing/here", "root"},
		{"the longest prefix wins", "/api/v2/orders", "api-v2"},
		{"a shorter prefix still wins when the longer one does not match", "/api/v1/orders", "api"},
		{"exact beats a longer-looking prefix", "/api/v2/health", "health"},
		{"exact does not match a subpath", "/api/v2/health/live", "api-v2"},
		{"exact does not match a trailing slash", "/api/v2/health/", "api-v2"},
		{"ImplementationSpecific behaves as a prefix", "/legacy/thing", "legacy"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := table.Match("app.example.com", tc.path)
			if !ok {
				t.Fatalf("Match(%q) = _, false, want a match", tc.path)
			}
			if got.Backend.Service != tc.want {
				t.Errorf("Match(%q).Backend.Service = %q, want %q", tc.path, got.Backend.Service, tc.want)
			}
		})
	}
}

func TestPrefixMatchesOnSegmentBoundaries(t *testing.T) {
	// A prefix is a path prefix, not a string prefix. /foo must not swallow
	// /foobar, which would hand one application's traffic to another.
	table := routing.BuildTable([]routing.Ingress{
		ingress("app", "app.example.com",
			path("/foo", routing.PathTypePrefix, backend("foo")),
			path("/aaa/bbb/", routing.PathTypePrefix, backend("bbb")),
		),
	})

	tests := []struct {
		path      string
		want      string
		wantMatch bool
	}{
		{"/foo", "foo", true},
		{"/foo/", "foo", true},
		{"/foo/bar", "foo", true},
		{"/foobar", "", false},
		{"/foo.bar", "", false},
		{"/fo", "", false},
		{"/aaa/bbb", "bbb", true},
		{"/aaa/bbb/", "bbb", true},
		{"/aaa/bbb/ccc", "bbb", true},
		{"/aaa/bbbxyz", "", false},
		{"/aaa/bb", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got, ok := table.Match("app.example.com", tc.path)
			if ok != tc.wantMatch {
				t.Fatalf("Match(%q) = _, %t, want %t", tc.path, ok, tc.wantMatch)
			}
			if ok && got.Backend.Service != tc.want {
				t.Errorf("Match(%q).Backend.Service = %q, want %q", tc.path, got.Backend.Service, tc.want)
			}
		})
	}
}

func TestRootPrefixMatchesEveryPath(t *testing.T) {
	table := routing.BuildTable([]routing.Ingress{
		ingress("app", "app.example.com", path("/", routing.PathTypePrefix, backend("root"))),
	})

	for _, p := range []string{"/", "/a", "/a/b", "/a.b", "//"} {
		if _, ok := table.Match("app.example.com", p); !ok {
			t.Errorf("Match(%q) = _, false, want a match", p)
		}
	}
}

func TestMatchReturnsNoRouteWhenNothingClaimsTheRequest(t *testing.T) {
	table := routing.BuildTable([]routing.Ingress{
		ingress("app", "app.example.com", path("/api", routing.PathTypePrefix, backend("api"))),
	})

	if _, ok := table.Match("other.example.com", "/api"); ok {
		t.Error("Match() on an unknown host = _, true, want no match")
	}
	if _, ok := table.Match("app.example.com", "/other"); ok {
		t.Error("Match() on an unclaimed path = _, true, want no match")
	}
}

func TestNilTableMatchesNothing(t *testing.T) {
	// Requests can arrive before the first snapshot is installed. That must
	// be a 404, not a panic.
	var table *routing.Table
	if _, ok := table.Match("app.example.com", "/"); ok {
		t.Error("Match() on a nil table = _, true, want no match")
	}
	if _, ok := table.Certificate("app.example.com"); ok {
		t.Error("Certificate() on a nil table = _, true, want none")
	}
	if table.HasHost("app.example.com") {
		t.Error("HasHost() on a nil table = true, want false")
	}
	if got := table.Hosts(); len(got) != 0 {
		t.Errorf("Hosts() on a nil table = %v, want empty", got)
	}
}

func TestDefaultBackendIsTheLastResort(t *testing.T) {
	def := backend("default")
	table := routing.BuildTable([]routing.Ingress{
		{
			Namespace:      "apps",
			Name:           "app",
			Rules:          []routing.HostRule{{Host: "app.example.com", Paths: []routing.PathRule{path("/api", routing.PathTypePrefix, backend("api"))}}},
			DefaultBackend: &def,
		},
	})

	tests := []struct {
		name string
		host string
		path string
		want string
	}{
		{"a claimed path still wins", "app.example.com", "/api", "api"},
		{"an unclaimed path on a known host", "app.example.com", "/other", "default"},
		{"an unknown host", "elsewhere.example.org", "/", "default"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := table.Match(tc.host, tc.path)
			if !ok {
				t.Fatalf("Match(%q, %q) = _, false, want a match", tc.host, tc.path)
			}
			if got.Backend.Service != tc.want {
				t.Errorf("Backend.Service = %q, want %q", got.Backend.Service, tc.want)
			}
		})
	}
}

func TestMatchReportsTheOwningIngress(t *testing.T) {
	// Authorisation resolves its targets by Ingress name (ADR 0002), so the
	// match has to say which Ingress produced it.
	table := routing.BuildTable([]routing.Ingress{
		ingress("shop", "app.example.com", path("/", routing.PathTypePrefix, backend("shop"))),
	})

	got, ok := table.Match("app.example.com", "/")
	if !ok {
		t.Fatal("Match() = _, false, want a match")
	}
	want := routing.ResourceRef{Namespace: "apps", Name: "shop"}
	if got.Ingress != want {
		t.Errorf("Match().Ingress = %+v, want %+v", got.Ingress, want)
	}
}

func TestConflictingRoutesResolveToTheOldestIngress(t *testing.T) {
	// Two Ingresses claiming the same host and path is a mistake, but it
	// must not make routing depend on the order the informer happened to
	// list them in. The older resource keeps the route.
	older := routing.Ingress{
		Namespace: "apps", Name: "zzz-older",
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Rules:     []routing.HostRule{{Host: "app.example.com", Paths: []routing.PathRule{path("/", routing.PathTypePrefix, backend("older"))}}},
	}
	newer := routing.Ingress{
		Namespace: "apps", Name: "aaa-newer",
		CreatedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		Rules:     []routing.HostRule{{Host: "app.example.com", Paths: []routing.PathRule{path("/", routing.PathTypePrefix, backend("newer"))}}},
	}

	for _, order := range [][]routing.Ingress{{older, newer}, {newer, older}} {
		got, ok := routing.BuildTable(order).Match("app.example.com", "/")
		if !ok {
			t.Fatal("Match() = _, false, want a match")
		}
		if got.Backend.Service != "older" {
			t.Errorf("Backend.Service = %q, want %q", got.Backend.Service, "older")
		}
	}
}

func TestSameAgeConflictsResolveByName(t *testing.T) {
	// Creation timestamps have one-second granularity, so ties are common.
	// Namespace and name break them.
	a := ingress("aaa", "app.example.com", path("/", routing.PathTypePrefix, backend("aaa")))
	b := ingress("bbb", "app.example.com", path("/", routing.PathTypePrefix, backend("bbb")))

	for _, order := range [][]routing.Ingress{{a, b}, {b, a}} {
		got, _ := routing.BuildTable(order).Match("app.example.com", "/")
		if got.Backend.Service != "aaa" {
			t.Errorf("Backend.Service = %q, want %q", got.Backend.Service, "aaa")
		}
	}
}

func TestCertificateLookup(t *testing.T) {
	table := routing.BuildTable([]routing.Ingress{
		{
			Namespace: "apps", Name: "app",
			Rules: []routing.HostRule{{Host: "app.example.com", Paths: []routing.PathRule{path("/", routing.PathTypePrefix, backend("app"))}}},
			TLS: []routing.TLSBlock{
				{Hosts: []string{"app.example.com"}, SecretName: "app-tls"},
				{Hosts: []string{"*.example.com"}, SecretName: "wildcard-tls"},
			},
		},
	})

	tests := []struct {
		name      string
		host      string
		want      routing.SecretRef
		wantFound bool
	}{
		{"exact beats the wildcard", "app.example.com", routing.SecretRef{Namespace: "apps", Name: "app-tls"}, true},
		{"a sibling label uses the wildcard", "other.example.com", routing.SecretRef{Namespace: "apps", Name: "wildcard-tls"}, true},
		{"case does not matter", "APP.EXAMPLE.COM", routing.SecretRef{Namespace: "apps", Name: "app-tls"}, true},
		{"an unlisted host has no certificate", "elsewhere.example.org", routing.SecretRef{}, false},
		{"the bare domain is not covered by the wildcard", "example.com", routing.SecretRef{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := table.Certificate(tc.host)
			if ok != tc.wantFound {
				t.Fatalf("Certificate(%q) = _, %t, want %t", tc.host, ok, tc.wantFound)
			}
			if got != tc.want {
				t.Errorf("Certificate(%q) = %+v, want %+v", tc.host, got, tc.want)
			}
		})
	}
}

func TestCertificateConflictsResolveDeterministically(t *testing.T) {
	older := routing.Ingress{
		Namespace: "apps", Name: "zzz",
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		TLS:       []routing.TLSBlock{{Hosts: []string{"app.example.com"}, SecretName: "older-tls"}},
	}
	newer := routing.Ingress{
		Namespace: "apps", Name: "aaa",
		CreatedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		TLS:       []routing.TLSBlock{{Hosts: []string{"app.example.com"}, SecretName: "newer-tls"}},
	}

	for _, order := range [][]routing.Ingress{{older, newer}, {newer, older}} {
		got, ok := routing.BuildTable(order).Certificate("app.example.com")
		if !ok {
			t.Fatal("Certificate() = _, false, want a certificate")
		}
		if got.Name != "older-tls" {
			t.Errorf("Certificate().Name = %q, want %q", got.Name, "older-tls")
		}
	}
}

func TestHostsAndHasHost(t *testing.T) {
	// The set of routed hosts bounds where the login flow may hand a request
	// back to, so it has to include every host the table knows about.
	table := routing.BuildTable([]routing.Ingress{
		ingress("app", "app.example.com", path("/", routing.PathTypePrefix, backend("app"))),
		ingress("wild", "*.example.org", path("/", routing.PathTypePrefix, backend("wild"))),
		{
			Namespace: "apps", Name: "tls-only",
			TLS: []routing.TLSBlock{{Hosts: []string{"tls.example.com"}, SecretName: "tls"}},
		},
		ingress("hostless", "", path("/", routing.PathTypePrefix, backend("hostless"))),
	})

	got := table.Hosts()
	want := []string{"*.example.org", "app.example.com", "tls.example.com"}
	if len(got) != len(want) {
		t.Fatalf("Hosts() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Hosts() = %v, want %v (sorted)", got, want)
		}
	}

	tests := []struct {
		host string
		want bool
	}{
		{"app.example.com", true},
		{"APP.example.com", true},
		{"tls.example.com", true},
		{"anything.example.org", true},
		{"example.org", false},
		{"elsewhere.example.net", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := table.HasHost(tc.host); got != tc.want {
			t.Errorf("HasHost(%q) = %t, want %t", tc.host, got, tc.want)
		}
	}
}

func TestBuildTableSkipsUnusableRules(t *testing.T) {
	// A rule with no service names nothing to forward to. Dropping it keeps
	// the rest of the Ingress working instead of routing to nowhere.
	table := routing.BuildTable([]routing.Ingress{
		ingress("app", "app.example.com",
			path("/broken", routing.PathTypePrefix, routing.Backend{Namespace: "apps"}),
			path("/ok", routing.PathTypePrefix, backend("ok")),
		),
	})

	if _, ok := table.Match("app.example.com", "/broken"); ok {
		t.Error("Match() on a rule without a service = _, true, want no match")
	}
	if _, ok := table.Match("app.example.com", "/ok"); !ok {
		t.Error("Match() on the healthy rule = _, false, want a match")
	}
}

func TestEmptyPathIsTreatedAsRoot(t *testing.T) {
	// ImplementationSpecific allows an empty path. Treating it as the root
	// prefix is the only reading that forwards anything at all.
	table := routing.BuildTable([]routing.Ingress{
		ingress("app", "app.example.com", path("", routing.PathTypeImplementationSpecific, backend("app"))),
	})

	if _, ok := table.Match("app.example.com", "/anything"); !ok {
		t.Error("Match() = _, false, want a match")
	}
}

func TestMatchNormalisesTheRequestPath(t *testing.T) {
	// A request line may carry an empty or relative path. Anything that is
	// not rooted is treated as the root so that matching stays total.
	table := routing.BuildTable([]routing.Ingress{
		ingress("app", "app.example.com", path("/", routing.PathTypePrefix, backend("root"))),
	})

	for _, p := range []string{"", "*"} {
		if _, ok := table.Match("app.example.com", p); !ok {
			t.Errorf("Match(%q) = _, false, want a match", p)
		}
	}
}
