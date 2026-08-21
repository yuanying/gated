// Package routing turns a set of routed resources into a lookup table and
// answers "where does this request go?" against it.
//
// Nothing here knows about Kubernetes. The input types are neutral copies of
// what an Ingress expresses — hosts, paths, path types, a backend identifier —
// so that every matching rule can be enumerated in a table test without an API
// server (ADR 0007). Translating Kubernetes objects into these types is the
// job of the package that watches them.
package routing

import "time"

// PathType is how a path in a rule is compared against a request path. The
// vocabulary is the one Ingress offers, and no more (ADR 0001).
type PathType string

const (
	// PathTypeExact matches the request path in full.
	PathTypeExact PathType = "Exact"
	// PathTypePrefix matches on whole path segments.
	PathTypePrefix PathType = "Prefix"
	// PathTypeImplementationSpecific leaves the meaning to the controller.
	// gated reads it as Prefix, which is what the widely used controllers
	// settled on and what existing manifests therefore expect.
	PathTypeImplementationSpecific PathType = "ImplementationSpecific"
)

// Backend names where a matched request is forwarded to. It is a Service and
// a port, spelled without any Kubernetes type: resolving it to an address is
// somebody else's problem.
//
// Exactly one of PortName and PortNumber is meaningful, mirroring the choice
// an Ingress makes.
type Backend struct {
	Namespace  string
	Service    string
	PortName   string
	PortNumber int32
}

// isZero reports whether the backend names nothing to forward to.
func (b Backend) isZero() bool {
	return b.Service == "" || b.Namespace == ""
}

// PathRule is one path of one host, and where it leads.
type PathRule struct {
	Path     string
	PathType PathType
	Backend  Backend
}

// HostRule is the set of paths claimed for one host. An empty Host claims the
// paths for every host that nothing more specific covers.
type HostRule struct {
	Host  string
	Paths []PathRule
}

// TLSBlock ties a set of hosts to the Secret holding their certificate.
type TLSBlock struct {
	Hosts      []string
	SecretName string
}

// Ingress is the neutral form of one routed resource.
type Ingress struct {
	Namespace string
	Name      string
	// CreatedAt orders conflicting claims. Two resources claiming the same
	// host and path is a mistake; resolving it by age rather than by list
	// order keeps the outcome the same on every replica and across restarts.
	CreatedAt time.Time

	Rules          []HostRule
	DefaultBackend *Backend
	TLS            []TLSBlock
}

// ResourceRef identifies the resource a route came from. Authorisation names
// its targets this way (ADR 0002), so a match has to carry it.
type ResourceRef struct {
	Namespace string
	Name      string
}

// SecretRef identifies a Secret.
type SecretRef struct {
	Namespace string
	Name      string
}

// Match is the outcome of a successful lookup.
type Match struct {
	Backend Backend
	Ingress ResourceRef
	// Path and PathType are the rule that matched, kept for logging and for
	// telling apart a default backend (an empty Path) from a real route.
	Path     string
	PathType PathType
}
