package routing

import (
	"net"
	"sort"
	"strings"
)

// Table is an immutable snapshot of every route in force. Build one with
// BuildTable and swap it in whole; lookups take no locks because the table is
// never mutated after it is built.
//
// The zero value and a nil *Table answer "no route", so requests that arrive
// before the first snapshot is installed get a 404 rather than a panic.
type Table struct {
	exactHosts    map[string]*hostRoutes
	wildcardHosts map[string]*hostRoutes
	hostless      *hostRoutes

	defaultBackend *route

	exactCerts    map[string]SecretRef
	wildcardCerts map[string]SecretRef

	// hosts is every host any resource declared, in the form it was written
	// in, sorted. The login flow bounds its redirect targets with this
	// (design contract: no open redirect).
	hosts []string
	// hostSet mirrors hosts for membership tests, split by tier.
	exactHostSet    map[string]struct{}
	wildcardHostSet map[string]struct{}
}

// hostRoutes holds the paths claimed for one host.
type hostRoutes struct {
	exact map[string]route
	// prefixes are ordered longest first, so the first hit is the most
	// specific one.
	prefixes []prefixRoute
}

type route struct {
	backend  Backend
	ingress  ResourceRef
	path     string
	pathType PathType
}

type prefixRoute struct {
	prefix string
	route  route
}

// BuildTable compiles the routes of every resource into a snapshot.
//
// Conflicting claims — the same host and path declared twice — are resolved in
// favour of the older resource, and among resources of the same age by
// namespace and name. The order the caller lists the resources in never
// affects the result.
func BuildTable(ingresses []Ingress) *Table {
	ordered := make([]Ingress, len(ingresses))
	copy(ordered, ingresses)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.Before(b.CreatedAt)
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})

	t := &Table{
		exactHosts:      map[string]*hostRoutes{},
		wildcardHosts:   map[string]*hostRoutes{},
		exactCerts:      map[string]SecretRef{},
		wildcardCerts:   map[string]SecretRef{},
		exactHostSet:    map[string]struct{}{},
		wildcardHostSet: map[string]struct{}{},
	}
	declared := map[string]struct{}{}

	for _, ing := range ordered {
		ref := ResourceRef{Namespace: ing.Namespace, Name: ing.Name}

		for _, hr := range ing.Rules {
			host, wildcard, ok := classifyHost(hr.Host)
			if hr.Host != "" {
				if !ok {
					continue
				}
				declared[strings.ToLower(strings.TrimSuffix(hr.Host, "."))] = struct{}{}
				if wildcard {
					t.wildcardHostSet[host] = struct{}{}
				} else {
					t.exactHostSet[host] = struct{}{}
				}
			}
			target := t.routesFor(hr.Host, host, wildcard)
			for _, p := range hr.Paths {
				if p.Backend.isZero() {
					continue
				}
				target.add(p, ref)
			}
		}

		if ing.DefaultBackend != nil && t.defaultBackend == nil && !ing.DefaultBackend.isZero() {
			t.defaultBackend = &route{backend: *ing.DefaultBackend, ingress: ref}
		}

		for _, block := range ing.TLS {
			if block.SecretName == "" {
				continue
			}
			secret := SecretRef{Namespace: ing.Namespace, Name: block.SecretName}
			for _, h := range block.Hosts {
				host, wildcard, ok := classifyHost(h)
				if !ok || host == "" {
					continue
				}
				declared[strings.ToLower(strings.TrimSuffix(h, "."))] = struct{}{}
				if wildcard {
					t.wildcardHostSet[host] = struct{}{}
					if _, dup := t.wildcardCerts[host]; !dup {
						t.wildcardCerts[host] = secret
					}
					continue
				}
				t.exactHostSet[host] = struct{}{}
				if _, dup := t.exactCerts[host]; !dup {
					t.exactCerts[host] = secret
				}
			}
		}
	}

	t.hosts = make([]string, 0, len(declared))
	for h := range declared {
		t.hosts = append(t.hosts, h)
	}
	sort.Strings(t.hosts)

	for _, hr := range t.exactHosts {
		hr.sortPrefixes()
	}
	for _, hr := range t.wildcardHosts {
		hr.sortPrefixes()
	}
	if t.hostless != nil {
		t.hostless.sortPrefixes()
	}
	return t
}

// routesFor returns the bucket a host's paths belong in, creating it on first
// use.
func (t *Table) routesFor(raw, host string, wildcard bool) *hostRoutes {
	if raw == "" {
		if t.hostless == nil {
			t.hostless = newHostRoutes()
		}
		return t.hostless
	}
	set := t.exactHosts
	if wildcard {
		set = t.wildcardHosts
	}
	if existing, ok := set[host]; ok {
		return existing
	}
	created := newHostRoutes()
	set[host] = created
	return created
}

func newHostRoutes() *hostRoutes {
	return &hostRoutes{exact: map[string]route{}}
}

// add records one path rule, leaving an already recorded claim in place.
func (h *hostRoutes) add(p PathRule, ref ResourceRef) {
	r := route{backend: p.Backend, ingress: ref, path: p.Path, pathType: p.PathType}
	if p.PathType == PathTypeExact {
		key := normalizeRulePath(p.Path)
		if _, dup := h.exact[key]; !dup {
			h.exact[key] = r
		}
		return
	}
	key := normalizeRulePath(p.Path)
	for _, existing := range h.prefixes {
		if existing.prefix == key {
			return
		}
	}
	h.prefixes = append(h.prefixes, prefixRoute{prefix: key, route: r})
}

// sortPrefixes puts the longest prefix first. The sort is stable, so equally
// long prefixes keep the order the resources were considered in.
func (h *hostRoutes) sortPrefixes() {
	sort.SliceStable(h.prefixes, func(i, j int) bool {
		return len(h.prefixes[i].prefix) > len(h.prefixes[j].prefix)
	})
}

// match finds the most specific rule for an already normalised request path.
func (h *hostRoutes) match(path string) (route, bool) {
	if h == nil {
		return route{}, false
	}
	if r, ok := h.exact[path]; ok {
		return r, true
	}
	for _, p := range h.prefixes {
		if prefixMatches(p.prefix, path) {
			return p.route, true
		}
	}
	return route{}, false
}

// Match decides where a request goes.
//
// Hosts are consulted from the most specific tier to the least: an exact host,
// then a wildcard covering it, then the rules that name no host at all. A tier
// that knows the host but claims none of its paths does not end the search —
// the next tier still gets to answer — and the resource-wide default backend
// is the last resort.
func (t *Table) Match(host, path string) (Match, bool) {
	if t == nil {
		return Match{}, false
	}
	h := CanonicalHost(host)
	p := normalizeRequestPath(path)

	for _, candidate := range t.candidates(h) {
		if r, ok := candidate.match(p); ok {
			return Match{Backend: r.backend, Ingress: r.ingress, Path: r.path, PathType: r.pathType}, true
		}
	}
	if t.defaultBackend != nil {
		return Match{Backend: t.defaultBackend.backend, Ingress: t.defaultBackend.ingress}, true
	}
	return Match{}, false
}

// candidates lists the host buckets to try, most specific first.
func (t *Table) candidates(host string) []*hostRoutes {
	out := make([]*hostRoutes, 0, 3)
	if r, ok := t.exactHosts[host]; ok {
		out = append(out, r)
	}
	if parent, ok := wildcardParent(host); ok {
		if r, ok := t.wildcardHosts[parent]; ok {
			out = append(out, r)
		}
	}
	if t.hostless != nil {
		out = append(out, t.hostless)
	}
	return out
}

// Certificate returns the Secret holding the certificate for a host, using the
// same exact-before-wildcard precedence as routing.
func (t *Table) Certificate(host string) (SecretRef, bool) {
	if t == nil {
		return SecretRef{}, false
	}
	h := CanonicalHost(host)
	if ref, ok := t.exactCerts[h]; ok {
		return ref, true
	}
	if parent, ok := wildcardParent(h); ok {
		if ref, ok := t.wildcardCerts[parent]; ok {
			return ref, true
		}
	}
	return SecretRef{}, false
}

// HasHost reports whether any resource claims this host, by name or through a
// wildcard. Rules that name no host do not count: they answer for hosts the
// table never heard of, which is exactly what a caller asking this question
// wants to exclude.
func (t *Table) HasHost(host string) bool {
	if t == nil {
		return false
	}
	h := CanonicalHost(host)
	if h == "" {
		return false
	}
	if _, ok := t.exactHostSet[h]; ok {
		return true
	}
	if parent, ok := wildcardParent(h); ok {
		if _, ok := t.wildcardHostSet[parent]; ok {
			return true
		}
	}
	return false
}

// Hosts returns every declared host, sorted, in the form it was written in —
// wildcards keep their leading "*.".
func (t *Table) Hosts() []string {
	if t == nil {
		return nil
	}
	out := make([]string, len(t.hosts))
	copy(out, t.hosts)
	return out
}

// CanonicalHost reduces a Host header or an SNI name to the form hosts are
// compared in: lower case, without a port and without the root label's
// trailing dot.
func CanonicalHost(host string) string {
	h := host
	if strings.Contains(h, ":") {
		if hostOnly, _, err := net.SplitHostPort(h); err == nil {
			h = hostOnly
		}
	}
	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(h)
}

// classifyHost splits a declared host into its comparison key and whether it
// is a wildcard. A wildcard is "*." followed by at least one label; anything
// else containing "*" is not something Ingress can express, and is dropped.
func classifyHost(host string) (key string, wildcard bool, ok bool) {
	h := CanonicalHost(host)
	if h == "" {
		return "", false, true
	}
	if rest, found := strings.CutPrefix(h, "*."); found {
		if rest == "" || strings.Contains(rest, "*") {
			return "", false, false
		}
		return rest, true, true
	}
	if strings.Contains(h, "*") {
		return "", false, false
	}
	return h, false, true
}

// wildcardParent returns the host a wildcard would have to cover to match this
// host. "a.example.com" yields "example.com"; a single label yields nothing,
// because a wildcard always stands for exactly one label.
func wildcardParent(host string) (string, bool) {
	_, parent, found := strings.Cut(host, ".")
	if !found || parent == "" {
		return "", false
	}
	return parent, true
}

// normalizeRulePath makes a declared path comparable: rooted, and without a
// trailing slash that would otherwise make "/a/" and "/a" different rules.
func normalizeRulePath(p string) string {
	if p == "" || !strings.HasPrefix(p, "/") {
		return "/"
	}
	if p == "/" {
		return p
	}
	return strings.TrimRight(p, "/")
}

// normalizeRequestPath keeps matching total: a request line that carries no
// path, or the asterisk-form of OPTIONS, is treated as the root.
func normalizeRequestPath(p string) string {
	if p == "" || !strings.HasPrefix(p, "/") {
		return "/"
	}
	return p
}

// prefixMatches compares on whole path segments, so that "/foo" claims
// "/foo/bar" but not "/foobar".
func prefixMatches(prefix, path string) bool {
	if prefix == "/" {
		return true
	}
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}
