package acme

// The label gated puts on the Secrets it creates itself.
//
// It marks provenance and nothing more: gated never refuses to read a Secret
// for lacking it, because a certificate placed by hand is exactly the case ADR
// 0005 says to leave alone.
const (
	ManagedByLabel = "app.kubernetes.io/managed-by"
	ManagedByValue = "gated"
)
