package acme

import "context"

// The challenge types gated knows how to compute a response for. HTTP-01 is
// the only one with a solver today (ADR 0005); DNS-01 is named here because
// the response for it is computed differently, and that difference is the
// whole of what the client has to know about a second solver.
const (
	ChallengeHTTP01 = "http-01"
	ChallengeDNS01  = "dns-01"
)

// Challenge is one outstanding validation, in the terms a solver needs.
//
// Response is what the solver has to publish: for HTTP-01 the key
// authorization served under the well-known path, for DNS-01 the value of the
// TXT record. Computing it is the client's job, so a solver never touches the
// account key.
type Challenge struct {
	// Type is the ACME challenge type, one of the constants above.
	Type string
	// Identifier is the name being validated, without a wildcard label.
	Identifier string
	// Wildcard says the authorization covers "*." in front of Identifier.
	Wildcard bool
	// Token is the challenge token, which for HTTP-01 is also the last
	// path segment the validation server asks for.
	Token string
	// Response is the value the solver publishes.
	Response string
}

// Solver makes a challenge answerable and takes it back down again.
//
// Present must not return until every replica can answer, not only the one
// that called it: the validation server reaches whichever replica the load
// balancer hands it, and an answer that has not propagated fails the order
// (ADR 0006).
//
// CleanUp is called for every challenge that was presented, including on the
// paths where the order failed, and has to tolerate a challenge that is
// already gone.
type Solver interface {
	// Type is the ACME challenge type this solver answers.
	Type() string
	Present(ctx context.Context, ch Challenge) error
	CleanUp(ctx context.Context, ch Challenge) error
}
