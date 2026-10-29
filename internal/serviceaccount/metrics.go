package serviceaccount

import "github.com/prometheus/client_golang/prometheus"

// Metrics are the series ServiceAccount tokens are counted in (ADR 0031,
// ADR 0039).
//
// They are labelled by outcome and by nothing else. The ServiceAccount a token
// belonged to is a principal, and a principal is the access log's to record,
// not a label's (ADR 0031).
type Metrics struct {
	tokens  *prometheus.CounterVec
	reviews *prometheus.CounterVec
}

// NewMetrics registers the metrics with reg and returns them.
//
// It panics if they are already registered, which is what registering the
// same collector twice in one process means.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		tokens: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gated_serviceaccount_tokens_total",
			Help: "ServiceAccount tokens presented, by whether they were accepted and why not.",
		}, []string{"result"}),
		reviews: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gated_serviceaccount_token_reviews_total",
			Help: "TokenReviews sent to the API server, by what it answered.",
		}, []string{"result"}),
	}
	reg.MustRegister(m.tokens, m.reviews)
	return m
}

// The answers a TokenReview is counted by.
const (
	reviewAuthenticated   = "authenticated"
	reviewUnauthenticated = "unauthenticated"
	reviewError           = "error"
)

func (m *Metrics) token(reason Reason) {
	if m == nil {
		return
	}
	m.tokens.WithLabelValues(string(reason)).Inc()
}

func (m *Metrics) review(result string) {
	if m == nil {
		return
	}
	m.reviews.WithLabelValues(result).Inc()
}
