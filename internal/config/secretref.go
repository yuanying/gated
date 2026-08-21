package config

import (
	"fmt"
	"strings"
)

// SecretRef names a Secret. It satisfies flag.Value, parsing the
// namespace/name form.
//
// The namespace is always spelled out. Falling back to "the namespace gated
// runs in" would make the meaning of a flag depend on the deployment.
type SecretRef struct {
	Namespace string
	Name      string
}

// IsZero reports whether the reference is unset.
func (r SecretRef) IsZero() bool { return r.Namespace == "" && r.Name == "" }

// String renders the reference in the form Set accepts.
func (r SecretRef) String() string {
	if r.IsZero() {
		return ""
	}
	return r.Namespace + "/" + r.Name
}

// Set parses the namespace/name form.
func (r *SecretRef) Set(s string) error {
	parts := strings.Split(s, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("%q is not of the form namespace/name", s)
	}
	r.Namespace, r.Name = parts[0], parts[1]
	return nil
}

// SecretKeyRef names one entry inside a Secret. It satisfies flag.Value,
// parsing the namespace/name/key form.
type SecretKeyRef struct {
	Namespace string
	Name      string
	Key       string
}

// IsZero reports whether the reference is unset.
func (r SecretKeyRef) IsZero() bool {
	return r.Namespace == "" && r.Name == "" && r.Key == ""
}

// String renders the reference in the form Set accepts.
func (r SecretKeyRef) String() string {
	if r.IsZero() {
		return ""
	}
	return r.Namespace + "/" + r.Name + "/" + r.Key
}

// Set parses the namespace/name/key form.
func (r *SecretKeyRef) Set(s string) error {
	parts := strings.Split(s, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return fmt.Errorf("%q is not of the form namespace/name/key", s)
	}
	r.Namespace, r.Name, r.Key = parts[0], parts[1], parts[2]
	return nil
}
