package controller

// The permissions gated needs, in one place.
//
// They are markers rather than a hand-written manifest so that the manifest
// cannot drift from the code: `make generate` rewrites config/rbac/role.yaml
// from what is declared here (ADR 0011). Each block says which part of the
// process needs it, because the only way to keep the set narrow is to be able
// to tell what a verb was added for.
//
// Nothing here grants anything cluster-wide that is not read cluster-wide.
// gated has to see Ingresses in every namespace to route them, so its role is
// a ClusterRole; the writes it makes are to its own resources' status, to the
// Secrets it is told to manage, and to the Lease it elects a leader with.

// Routing reads the Ingresses it is responsible for and the IngressClass that
// says which those are (ADR 0012). It never writes to them.
//
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingressclasses,verbs=get;list;watch

// The proxy resolves a routed backend to the Service's cluster IP (ADR 0013),
// so it reads Services and nothing else about a workload.
//
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch

// Secrets carry everything replicas share (ADR 0006): the certificates TLS is
// terminated with, the ACME account key, the HTTP-01 challenge tokens, the
// session signing key and the generated access tokens. gated creates and
// updates the ones it manages; it never deletes a Secret, so a certificate
// placed by hand cannot be destroyed by a bug here.
//
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch

// Failures that an operator has to see — a certificate that will not issue, a
// targetRef that resolves to nothing — are recorded as events on the object
// they concern (ADR 0002, ADR 0014).
//
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Leader election limits certificate issuance to one replica (ADR 0006). The
// Lease is the only object controller-runtime needs for it.
//
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch

// gated's own resources are read to decide requests and written back only in
// their status: what a targetRef resolved to, where a token landed, when it
// was last used (ADR 0002, ADR 0004). The spec is the operator's, and gated
// never edits it.
//
// +kubebuilder:rbac:groups=gate.unstable.cloud,resources=networkroles;networkrolebindings;accesstokens,verbs=get;list;watch
// +kubebuilder:rbac:groups=gate.unstable.cloud,resources=networkroles/status;networkrolebindings/status;accesstokens/status,verbs=get;update;patch
