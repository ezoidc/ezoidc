package server

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics tracks internal counters exposed to Prometheus via
// promhttp on a dedicated internal listener.
type Metrics struct {
	registry *prometheus.Registry
	// Number of JWT validation failures by reason
	jwtErrors *prometheus.CounterVec
	// Number of requests by endpoint and status code
	requests *prometheus.CounterVec
	// Number of variable grants by issuer, variable name and scope
	variables *prometheus.CounterVec
}

func NewMetrics() *Metrics {
	registry := prometheus.NewRegistry()
	jwtErrors := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ezoidc_jwt_errors_total",
			Help: "Total number of JWT validation failures by reason",
		},
		[]string{"reason"},
	)
	requests := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ezoidc_requests_total",
			Help: "Total number of HTTP requests by endpoint and status code",
		},
		[]string{"endpoint", "status"},
	)
	variables := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ezoidc_variables_allowed_total",
			Help: "Total number of variable grants by issuer, variable name and scope",
		},
		[]string{"issuer", "variable", "scope"},
	)

	registry.MustRegister(jwtErrors, requests, variables)
	return &Metrics{registry: registry, jwtErrors: jwtErrors, requests: requests, variables: variables}
}

// Record a JWT validation failure
func (m *Metrics) JWTError(reason string) {
	m.jwtErrors.WithLabelValues(reason).Inc()
}

// Record an HTTP request
func (m *Metrics) RequestRate(endpoint string, status int) {
	m.requests.WithLabelValues(endpoint, strconv.Itoa(status)).Inc()
}

// Record that an issuer was granted access to a variable
func (m *Metrics) AllowVariable(issuer, variable, scope string) {
	m.variables.WithLabelValues(issuer, variable, scope).Inc()
}

// Metrics endpoint handler serving the Prometheus text exposition format.
// Default registry collection is not used; the metrics registered on this
// instance are gathered.
func NewMetricsAPI(m *Metrics) *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())
	router.GET("/metrics", gin.WrapH(promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})))
	return router
}
