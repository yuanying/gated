package v1alpha1

// LabelFailClosed is the namespace label that closes the default for the
// Ingresses in that namespace (ADR 0041). With the value "true", an Ingress no
// NetworkRole resolves to is refused rather than served without
// authentication. Any other value, or no label at all, keeps the fail-open
// default of ADR 0002.
//
// The name and the value are a contract with whoever writes namespaces, so
// they do not change without a new ADR.
const LabelFailClosed = "gate.unstable.cloud/fail-closed"

// LabelFailClosedValue is the only value of LabelFailClosed that closes.
const LabelFailClosedValue = "true"
