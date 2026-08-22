package proxy

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yuanying/gated/internal/routing"
)

// HTTPMetrics are the series the data plane publishes (ADR 0031).
//
// Every one of them is labelled by the Ingress a request was routed to, and by
// nothing that a client controls. A path, a hostname or a principal as a label
// has no ceiling on the number of series it can create, and a metric is kept
// far longer than a log line.
type HTTPMetrics struct {
	requests       *prometheus.CounterVec
	duration       *prometheus.HistogramVec
	upstreamErrors *prometheus.CounterVec
}

// routeLabels name the Ingress a request was routed to. A request that
// matched nothing carries them empty rather than not at all.
var routeLabels = []string{"ingress_namespace", "ingress_name"}

// NewHTTPMetrics registers the request metrics with reg and returns them.
//
// It panics if the same metrics are already registered, which is what
// registering the same collector twice in one process means.
func NewHTTPMetrics(reg prometheus.Registerer) *HTTPMetrics {
	m := &HTTPMetrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gated_http_requests_total",
			Help: "Requests answered, by the Ingress that routed them.",
		}, append(append([]string{}, routeLabels...), "method", "code")),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "gated_http_request_duration_seconds",
			Help: "Time from the request arriving to the response being finished, by the Ingress that routed it.",
			// Reaching to half a minute: what gated forwards
			// includes streamed answers that are slow on purpose,
			// and a bucket set that stops at a second would put all
			// of them in +Inf.
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		}, routeLabels),
		upstreamErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gated_upstream_errors_total",
			Help: "Requests that ended in a 502, by the Ingress that routed them.",
		}, routeLabels),
	}
	reg.MustRegister(m.requests, m.duration, m.upstreamErrors)
	return m
}

// observe records one finished request. A nil HTTPMetrics records nothing, so
// that a handler can be wired without one.
func (m *HTTPMetrics) observe(ingress routing.ResourceRef, method string, status int, elapsed time.Duration, upstreamError bool) {
	if m == nil {
		return
	}
	m.requests.WithLabelValues(ingress.Namespace, ingress.Name, method, strconv.Itoa(status)).Inc()
	m.duration.WithLabelValues(ingress.Namespace, ingress.Name).Observe(elapsed.Seconds())
	if upstreamError {
		m.upstreamErrors.WithLabelValues(ingress.Namespace, ingress.Name).Inc()
	}
}
