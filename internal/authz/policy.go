package authz

// The neutral form of the two authorisation resources. A role protects a
// target and lists what may be done to it; a binding grants a role to
// subjects. Splitting them is what lets the same permissions be given to
// several people, and several permissions to the same person, without either
// list growing a copy of the other (ADR 0002).

// Rule is one grant of paths and methods. Rules never deny.
type Rule struct {
	// Paths in the vocabulary of RBAC nonResourceURLs.
	Paths []string
	// Methods are upper-case HTTP method names, or "*".
	Methods []string
}

// Role is a NetworkRole, with its target already resolved.
//
// Target is the zero value when the reference resolved to nothing. Such a role
// protects nothing at all — which is the fail-open hole ADR 0002 accepts and
// the reason the resolution is written back to the role's status.
type Role struct {
	Namespace string
	Name      string
	Target    ResourceRef
	Rules     []Rule
}

// Binding is a NetworkRoleBinding: a role name in the same namespace, and the
// subjects it is granted to.
type Binding struct {
	Namespace string
	RoleName  string
	Subjects  []string
}

// PolicySet is an immutable snapshot of every permission in force.
//
// Build one with BuildPolicySet and swap it in whole, the way the routing
// table is swapped: a request that is being authorised finishes against the
// set it started with, and the read side takes no locks.
type PolicySet struct {
	targets map[ResourceRef]*targetPolicy
}

// targetPolicy is everything said about one protected resource. Its presence
// in the set is what makes the resource protected, whether or not anything is
// granted on it.
type targetPolicy struct {
	grants []grant
}

// grant is one rule of one role, already joined to the subjects some binding
// gave that role.
type grant struct {
	paths   []string
	methods []string
	// anonymous is system:unauthenticated: everybody, logged in or not.
	anonymous bool
	// authenticated is system:authenticated: anybody who has logged in.
	authenticated bool
	// named are the subjects that stand for one account.
	named map[string]struct{}
}

// BuildPolicySet joins roles to the bindings that grant them.
//
// A role whose target did not resolve is skipped: it protects nothing, so
// recording it would make the resource it was meant to protect look protected
// while granting the whole world nothing.
//
// A binding reaches only the roles in its own namespace. Reaching across a
// namespace would let whoever can write a binding open up a resource in a
// namespace they do not own.
//
// The result holds no reference to the slices it was given, so the caller may
// go on using them.
func BuildPolicySet(roles []Role, bindings []Binding) *PolicySet {
	subjectsByRole := map[ResourceRef][]string{}
	for _, b := range bindings {
		key := ResourceRef{Namespace: b.Namespace, Name: b.RoleName}
		subjectsByRole[key] = append(subjectsByRole[key], b.Subjects...)
	}

	set := &PolicySet{targets: map[ResourceRef]*targetPolicy{}}
	for _, role := range roles {
		if role.Target.IsZero() {
			continue
		}
		target, ok := set.targets[role.Target]
		if !ok {
			target = &targetPolicy{}
			set.targets[role.Target] = target
		}

		subjects := subjectsByRole[ResourceRef{Namespace: role.Namespace, Name: role.Name}]
		if len(subjects) == 0 {
			// The role still protects the target; it just grants
			// nothing to anybody yet.
			continue
		}
		for _, rule := range role.Rules {
			if len(rule.Paths) == 0 || len(rule.Methods) == 0 {
				continue
			}
			target.grants = append(target.grants, newGrant(rule, subjects))
		}
	}
	return set
}

// newGrant copies one rule and sorts the subjects into the three kinds the
// decision asks about.
func newGrant(rule Rule, subjects []string) grant {
	g := grant{
		paths:   append([]string(nil), rule.Paths...),
		methods: append([]string(nil), rule.Methods...),
	}
	for _, s := range subjects {
		switch s {
		case SubjectUnauthenticated:
			g.anonymous = true
		case SubjectAuthenticated:
			g.authenticated = true
		case "":
			// A subject with no name matches nobody. It cannot
			// reach here through the API server, whose schema
			// requires a name, but an empty Subject on a request
			// means "not logged in" and must never match a grant.
		default:
			if g.named == nil {
				g.named = map[string]struct{}{}
			}
			g.named[s] = struct{}{}
		}
	}
	return g
}
