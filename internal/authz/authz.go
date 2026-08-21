// Package authz decides whether one request may proceed.
//
// Nothing here knows about Kubernetes or about HTTP. The input is a subject, a
// few attributes of the request and a set of permissions; the output is one of
// three answers (ADR 0007). Neither an informer cache nor an *http.Request can
// be handed to it, so every branch is reachable from a table test without an
// API server — which matters more here than anywhere else in gated, because a
// mistake in this decision does not fail loudly. It shows something to
// somebody who should not have seen it, and nobody reports that.
//
// Translating NetworkRole and NetworkRoleBinding objects into the types below
// is the job of the package that watches them, and turning a decision into an
// HTTP response — a login redirect, a 401 or a 403 — is the job of the proxy
// (ADR 0002).
package authz

import "strings"

// Decision is the answer to one authorisation question.
//
// The zero value is Deny. A decision that was never made must not read as
// permission granted.
type Decision int

const (
	// Deny means the request may not proceed, and logging in would not
	// change that.
	Deny Decision = iota
	// RequireLogin means the request may not proceed as it stands, but
	// somebody could pass here, so the caller is offered a login instead of
	// a refusal (ADR 0002).
	RequireLogin
	// Allow means the request may proceed.
	Allow
)

// String names the decision for logs and error messages.
func (d Decision) String() string {
	switch d {
	case Allow:
		return "Allow"
	case RequireLogin:
		return "RequireLogin"
	case Deny:
		return "Deny"
	default:
		return "Deny"
	}
}

// The subjects that stand for a class of caller rather than one account
// (ADR 0002). They are spelled here rather than imported from the API types,
// because this package holds no Kubernetes dependency; the CRD schema enforces
// the same spelling at admission.
const (
	// SubjectAuthenticated matches any caller who has logged in.
	SubjectAuthenticated = "system:authenticated"
	// SubjectUnauthenticated matches every caller, logged in or not.
	SubjectUnauthenticated = "system:unauthenticated"
)

// ResourceRef identifies a protected resource by namespace and name.
//
// The zero value names nothing. A request carrying it is not protected: either
// it was not routed to a resource at all, or the reference that was supposed
// to protect it did not resolve.
type ResourceRef struct {
	Namespace string
	Name      string
}

// IsZero reports whether the reference names nothing.
func (r ResourceRef) IsZero() bool { return r.Namespace == "" && r.Name == "" }

// String spells the reference the way Kubernetes does.
func (r ResourceRef) String() string {
	if r.IsZero() {
		return ""
	}
	return r.Namespace + "/" + r.Name
}

// Request is everything the decision is made from, besides the permissions.
//
// Host is carried because it is part of what a request is, and because it is
// what a person reads in a log line. It takes no part in the decision: what
// selects the permissions is Target, since a hostname can move from one
// resource to another and permissions are attached by name (ADR 0002).
type Request struct {
	// Subject is the principal behind the request, empty when the caller
	// has not logged in.
	Subject string
	// Host is the name the caller asked for.
	Host string
	// Path is the request path, as it arrived. It is not normalised, so
	// that the path authorised and the path forwarded are the same string
	// (ADR 0012).
	Path string
	// Method is the HTTP method, upper case as it arrived.
	Method string
	// Target is the resource the request was routed to, or the zero value
	// when it was routed to nothing.
	Target ResourceRef
}

// Evaluate answers whether the request may proceed.
//
// The rules only ever grant: a request is allowed as soon as any grant on its
// target covers the path and method for a subject it matches, so the answer
// never depends on the order the grants are held in and there is no rule that
// can take an allow back (ADR 0002).
//
// A nil PolicySet protects nothing and allows everything, which is the same
// answer it gives for a target no role names. The caller must therefore not
// evaluate against a set that has not been built yet: "nothing is loaded" and
// "nothing is protected" are the same value here, and telling them apart is
// the job of whoever owns the snapshot.
func (p *PolicySet) Evaluate(req Request) Decision {
	if p == nil || req.Target.IsZero() {
		return Allow
	}
	target, protected := p.targets[req.Target]
	if !protected {
		// ADR 0002: a resource no NetworkRole names is served without
		// authentication. Defaulting to a refusal here would mean every
		// public Ingress needed a policy saying "everyone", and a
		// policy that is on everything says nothing.
		return Allow
	}

	// couldPass records that somebody is allowed to do this, which is what
	// makes offering a login worth the caller's time.
	couldPass := false
	for i := range target.grants {
		g := &target.grants[i]
		if !g.covers(req.Path, req.Method) {
			continue
		}
		if g.anonymous {
			return Allow
		}
		if req.Subject == "" {
			couldPass = true
			continue
		}
		if g.authenticated {
			return Allow
		}
		if _, ok := g.named[req.Subject]; ok {
			return Allow
		}
	}

	if req.Subject == "" && couldPass {
		return RequireLogin
	}
	return Deny
}

// Protects reports whether any role names this resource. It is the same
// question Evaluate asks first, exposed for the sake of logs and tests.
func (p *PolicySet) Protects(ref ResourceRef) bool {
	if p == nil || ref.IsZero() {
		return false
	}
	_, ok := p.targets[ref]
	return ok
}

// covers reports whether this grant speaks about a path and a method.
//
// Paths and methods are ANDed within a rule, the way RBAC pairs
// nonResourceURLs with verbs: a rule covering /a with GET says nothing about
// POST /a.
func (g *grant) covers(path, method string) bool {
	return matchesAny(g.paths, path, pathMatches) && matchesAny(g.methods, method, methodMatches)
}

func matchesAny(patterns []string, value string, matches func(pattern, value string) bool) bool {
	for _, p := range patterns {
		if matches(p, value) {
			return true
		}
	}
	return false
}

// pathMatches compares one declared path against a request path, in the
// vocabulary RBAC uses for nonResourceURLs (ADR 0010): an exact path, a path
// ending in "*" which covers everything that starts with what precedes it, or
// "*" alone.
//
// The prefix is compared as a string, not as whole path segments, because that
// is what the vocabulary being borrowed means by it. Routing compares prefixes
// by segment (ADR 0012); the two are different questions. There, a wider match
// steals another application's traffic, and the author of the stolen route
// cannot see it happen. Here, a wider match grants more than was meant to the
// person who wrote the grant, and the CRD schema refuses any wildcard that is
// not the last character so that what is written is what is read.
func pathMatches(pattern, path string) bool {
	if pattern == "*" {
		return true
	}
	if prefix, found := strings.CutSuffix(pattern, "*"); found {
		return strings.HasPrefix(path, prefix)
	}
	return pattern == path
}

// methodMatches compares one declared method against the request's.
//
// The comparison is exact. HTTP method names are case sensitive and the
// vocabulary is upper case (ADR 0010), so folding case here would grant a
// little more than what was written, which is the direction that goes unseen.
func methodMatches(pattern, method string) bool {
	return pattern == "*" || pattern == method
}
