// Package policy translates NetworkRole and NetworkRoleBinding objects into
// the neutral permission set the authorisation decision is made against, and
// resolves the reference a role uses to name what it protects.
//
// The translation is a pure function over the API types: it reads no cache and
// contacts no server, so the resolution rules are covered by table tests.
// Keeping it out of internal/authz is what lets that package stay free of
// Kubernetes types (ADR 0007), the same way internal/ingress does for routing.
package policy

import (
	"sort"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"

	gatev1alpha1 "github.com/yuanying/gated/internal/apis/gate/v1alpha1"
	"github.com/yuanying/gated/internal/authz"
)

// TargetKey returns the object a role's targetRef names, and whether the
// reference is one gated can resolve at all.
//
// The namespace falls back to the role's own, which keeps the common case —
// a role written beside the Ingress it protects — short. The fallback lives
// here rather than in the CRD's defaults because the value differs per object
// and writing it into the stored spec would freeze it there (ADR 0010).
//
// A group or kind gated cannot resolve returns false. The schema refuses those
// at admission, but a decision that leaves a resource unprotected must not
// depend on admission having been in force when the object was written.
func TargetKey(role *gatev1alpha1.NetworkRole) (types.NamespacedName, bool) {
	ref := role.Spec.TargetRef
	if ref.Name == "" {
		return types.NamespacedName{}, false
	}
	group := ref.Group
	if group == "" {
		group = gatev1alpha1.TargetGroupNetworking
	}
	kind := ref.Kind
	if kind == "" {
		kind = gatev1alpha1.TargetKindIngress
	}
	if group != gatev1alpha1.TargetGroupNetworking || kind != gatev1alpha1.TargetKindIngress {
		return types.NamespacedName{}, false
	}
	namespace := ref.Namespace
	if namespace == "" {
		namespace = role.Namespace
	}
	return types.NamespacedName{Namespace: namespace, Name: ref.Name}, true
}

// Hosts lists the hostnames a resolved target serves, in the form they were
// written in, deduplicated and sorted.
//
// Both the routing rules and the tls blocks are read: a host named only in a
// tls block is still a name this resource answers to. They are what makes a
// resolution legible in the role's status — a name a person recognises, rather
// than only the name of an object (ADR 0002). Sorting them gives that status
// one canonical form, so reordering the rules of an Ingress does not rewrite
// the status of every role pointing at it.
func Hosts(ing *networkingv1.Ingress) []string {
	var out []string
	seen := map[string]struct{}{}
	add := func(host string) {
		if host == "" {
			return
		}
		if _, dup := seen[host]; dup {
			return
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}

	for _, rule := range ing.Spec.Rules {
		add(rule.Host)
	}
	for _, block := range ing.Spec.TLS {
		for _, host := range block.Hosts {
			add(host)
		}
	}
	sort.Strings(out)
	return out
}

// Build converts every role and binding into the neutral form, resolving each
// role's target against the Ingresses it is given.
//
// A role whose target does not resolve is kept, without a target. It protects
// nothing, and the decision has to be told so in order to let the request
// through (ADR 0002) — dropping it here and dropping it there would be the
// same outcome, but only one of them can be read back in a test.
func Build(
	roles []gatev1alpha1.NetworkRole,
	bindings []gatev1alpha1.NetworkRoleBinding,
	ingresses []networkingv1.Ingress,
) ([]authz.Role, []authz.Binding) {
	known := make(map[types.NamespacedName]struct{}, len(ingresses))
	for i := range ingresses {
		known[types.NamespacedName{Namespace: ingresses[i].Namespace, Name: ingresses[i].Name}] = struct{}{}
	}

	outRoles := make([]authz.Role, 0, len(roles))
	for i := range roles {
		role := &roles[i]
		converted := authz.Role{
			Namespace: role.Namespace,
			Name:      role.Name,
			Rules:     convertRules(role.Spec.Rules),
		}
		if key, ok := TargetKey(role); ok {
			if _, found := known[key]; found {
				converted.Target = authz.ResourceRef{Namespace: key.Namespace, Name: key.Name}
			}
		}
		outRoles = append(outRoles, converted)
	}

	outBindings := make([]authz.Binding, 0, len(bindings))
	for i := range bindings {
		binding := &bindings[i]
		converted := authz.Binding{
			Namespace: binding.Namespace,
			RoleName:  binding.Spec.RoleRef.Name,
		}
		for _, subject := range binding.Spec.Subjects {
			// Only User exists today (ADR 0002). A kind gated does
			// not know grants to nobody rather than to everybody.
			if subject.Kind != "" && subject.Kind != gatev1alpha1.SubjectKindUser {
				continue
			}
			converted.Subjects = append(converted.Subjects, subject.Name)
		}
		outBindings = append(outBindings, converted)
	}

	return outRoles, outBindings
}

// convertRules copies the rules of one role, dropping the API types.
func convertRules(rules []gatev1alpha1.NetworkRoleRule) []authz.Rule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]authz.Rule, 0, len(rules))
	for _, rule := range rules {
		converted := authz.Rule{Paths: append([]string(nil), rule.Paths...)}
		for _, method := range rule.Methods {
			converted.Methods = append(converted.Methods, string(method))
		}
		out = append(out, converted)
	}
	return out
}
