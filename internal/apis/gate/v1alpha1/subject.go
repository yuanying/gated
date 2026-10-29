package v1alpha1

// The subject vocabulary of ADR 0002. Identifiers are the human-readable name
// at the provider, not a numeric ID, so that a binding says who it grants to.
//
//	github:<login>          a single GitHub account
//	google:<mail address>   a single Google account
//	system:authenticated    anyone who has logged in
//	system:unauthenticated  anyone at all, logged in or not
//	system:serviceaccount:<namespace>:<name>
//	                        a single Kubernetes ServiceAccount, vouched for
//	                        by the API server through a TokenReview
//	                        (ADR 0039)
//
// The patterns below are enforced by the API server, so a typo that would
// silently grant nothing is rejected at admission instead.
const (
	// SubjectPattern accepts every subject the vocabulary defines.
	SubjectPattern = `^(github:[A-Za-z0-9][A-Za-z0-9-]{0,38}|google:[^@\s]+@[^@\s]+\.[^@\s]+|system:(authenticated|unauthenticated)|system:serviceaccount:[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?:[a-z0-9]([-a-z0-9.]*[a-z0-9])?)$`

	// NamedSubjectPattern accepts only subjects that name a real account.
	// The system: subjects are excluded: an AccessToken must belong to
	// someone, and a token that acts as "anyone" would grant every holder
	// of it whatever the anonymous rules grant, which needs no token. A
	// ServiceAccount is excluded too, although it names one principal: a
	// long-lived token must not pass for a workload whose own tokens the
	// API server issues, bounds and revokes (ADR 0039).
	NamedSubjectPattern = `^(github:[A-Za-z0-9][A-Za-z0-9-]{0,38}|google:[^@\s]+@[^@\s]+\.[^@\s]+)$`

	// SubjectAuthenticated matches anyone who has completed a login.
	SubjectAuthenticated = "system:authenticated"
	// SubjectUnauthenticated matches every request, logged in or not.
	SubjectUnauthenticated = "system:unauthenticated"

	// SubjectPrefixGitHub prefixes a GitHub login name.
	SubjectPrefixGitHub = "github:"
	// SubjectPrefixGoogle prefixes a Google mail address.
	SubjectPrefixGoogle = "google:"
	// SubjectPrefixServiceAccount prefixes the namespace and name of a
	// Kubernetes ServiceAccount, spelled as RBAC and the TokenReview
	// spell it.
	SubjectPrefixServiceAccount = "system:serviceaccount:"
)

// SubjectKind is the kind of principal a binding grants to.
//
// Only User exists today. Groups are deliberately absent (ADR 0002); adding
// them means adding a NetworkGroup resource and a Group kind here.
//
// +kubebuilder:validation:Enum=User
type SubjectKind string

// SubjectKindUser names a single principal.
const SubjectKindUser SubjectKind = "User"
