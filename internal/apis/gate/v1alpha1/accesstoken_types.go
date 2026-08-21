package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TokenSecretKey is the key of the generated token inside its Secret.
const TokenSecretKey = "token"

// TokenPrefix marks a value as a gated access token. Having a fixed prefix
// lets a leaked token be recognised for what it is by secret scanners.
const TokenPrefix = "gat_"

// AccessTokenSpec declares who a token acts as.
//
// The token itself is never written here. The controller generates it, stores
// it in a Secret and records only its hash in the status, so the spec stays
// something a person can write and review.
type AccessTokenSpec struct {
	// subject the token acts as: github:<login> or google:<mail address>.
	// The system: subjects are not accepted; a token has to belong to
	// someone.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^(github:[A-Za-z0-9][A-Za-z0-9-]{0,38}|google:[^@\s]+@[^@\s]+\.[^@\s]+)$`
	Subject string `json:"subject"`

	// secretName is the Secret the generated token is written to. Defaults
	// to the name of the AccessToken itself.
	//
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	// +optional
	SecretName string `json:"secretName,omitempty"`
}

// ConditionTokenIssued reports whether the token has been generated and
// stored.
const ConditionTokenIssued = "TokenIssued"

// AccessTokenStatus reports where the token landed and when it was last seen.
type AccessTokenStatus struct {
	// observedGeneration is the generation of the spec this status was
	// computed from.
	//
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// secretRef points at the Secret holding the generated token.
	//
	// +optional
	SecretRef *corev1.LocalObjectReference `json:"secretRef,omitempty"`

	// tokenHash is the SHA-256 of the generated token, in lower-case hex.
	// The proxy matches presented tokens against this hash so that it never
	// has to hold every token Secret in memory.
	//
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	// +optional
	TokenHash string `json:"tokenHash,omitempty"`

	// lastUsedTime is when a request last presented this token. It is
	// updated at a coarse granularity, so it shows that a token is in use
	// rather than exactly when.
	//
	// +optional
	LastUsedTime *metav1.Time `json:"lastUsedTime,omitempty"`

	// conditions of the token. TokenIssued is set to True once the Secret
	// holds a token.
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// AccessToken is a long-lived credential for clients that cannot follow a
// browser redirect (ADR 0004).
//
// It is accepted both as an Authorization: Bearer credential and in the
// password field of BASIC authentication. The latter looks like BASIC
// authentication on the wire but is not: the value is a revocable credential
// bound to one principal, not a shared password.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=gated,shortName=atoken
// +kubebuilder:printcolumn:name="Subject",type=string,JSONPath=`.spec.subject`
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.status.secretRef.name`
// +kubebuilder:printcolumn:name="Last Used",type=date,JSONPath=`.status.lastUsedTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type AccessToken struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec AccessTokenSpec `json:"spec"`

	// +optional
	Status AccessTokenStatus `json:"status,omitempty"`
}

// AccessTokenList is a list of AccessToken.
//
// +kubebuilder:object:root=true
type AccessTokenList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AccessToken `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AccessToken{}, &AccessTokenList{})
}
