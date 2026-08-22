package config

import (
	"fmt"
	"strings"
)

// ServiceRef names a Service. It is the same shape as SecretRef and kept
// apart from it so that a flag says what kind of object it expects.
type ServiceRef struct {
	Namespace string
	Name      string
}

// IsZero reports whether the reference is unset.
func (r ServiceRef) IsZero() bool { return r.Namespace == "" && r.Name == "" }

// String renders the reference in the form ServiceRefs.Set accepts.
func (r ServiceRef) String() string {
	if r.IsZero() {
		return ""
	}
	return r.Namespace + "/" + r.Name
}

// ServiceRefs collects the Services named by a repeatable flag.
//
// It satisfies flag.Value by appending rather than replacing: a deployment
// that is published through more than one Service — one per address family,
// for instance — names each of them (ADR 0032).
type ServiceRefs []ServiceRef

// String renders every reference, in the order they were given.
func (l *ServiceRefs) String() string {
	if l == nil || len(*l) == 0 {
		return ""
	}
	parts := make([]string, 0, len(*l))
	for _, ref := range *l {
		parts = append(parts, ref.String())
	}
	return strings.Join(parts, ",")
}

// Set parses one namespace/name and appends it.
func (l *ServiceRefs) Set(s string) error {
	parts := strings.Split(s, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("%q is not of the form namespace/name", s)
	}
	*l = append(*l, ServiceRef{Namespace: parts[0], Name: parts[1]})
	return nil
}

// Addresses collects the addresses named by a repeatable flag.
type Addresses []string

// String renders every address, in the order they were given.
func (l *Addresses) String() string {
	if l == nil {
		return ""
	}
	return strings.Join(*l, ",")
}

// Set appends one address.
//
// What an address has to look like is checked by Validate rather than here,
// so that a malformed one is reported beside every other startup problem
// instead of stopping the parse at the first (ADR 0009).
func (l *Addresses) Set(s string) error {
	*l = append(*l, s)
	return nil
}
