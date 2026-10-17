package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestMetricsPrometheus(t *testing.T) {
	m := NewMetrics()
	m.JWTError("invalid:jwt")
	m.JWTError("invalid:jwt")
	m.JWTError("invalid:claims:exp")
	m.AllowVariable("github", "api_key", "read")
	m.AllowVariable("github", "internal_token", "internal")
	m.RequestRate("variables", 200)
	m.RequestRate("variables", 401)

	out := scrape(t, m)
	assert.Contains(t, out, "# HELP ezoidc_jwt_errors_total Total number of JWT validation failures by reason")
	assert.Contains(t, out, "# TYPE ezoidc_jwt_errors_total counter")
	assert.Contains(t, out, `ezoidc_jwt_errors_total{reason="invalid:jwt"} 2`)
	assert.Contains(t, out, `ezoidc_jwt_errors_total{reason="invalid:claims:exp"} 1`)
	assert.Contains(t, out, `ezoidc_variables_allowed_total{issuer="github",scope="read",variable="api_key"} 1`)
	assert.Contains(t, out, `ezoidc_variables_allowed_total{issuer="github",scope="internal",variable="internal_token"} 1`)
	assert.Contains(t, out, `ezoidc_requests_total{endpoint="variables",status="200"} 1`)
	assert.Contains(t, out, `ezoidc_requests_total{endpoint="variables",status="401"} 1`)
}

func TestMetricsAPI(t *testing.T) {
	m := NewMetrics()
	m.JWTError("invalid:jwt")
	m.AllowVariable("github", "api_key", "read")

	g := NewMetricsAPI(m)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	g.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/plain")
	assert.Contains(t, w.Body.String(), `ezoidc_jwt_errors_total{reason="invalid:jwt"} 1`)
	assert.Contains(t, w.Body.String(), `ezoidc_variables_allowed_total{issuer="github",scope="read",variable="api_key"} 1`)
}

func TestRecordRequest(t *testing.T) {
	m := NewMetrics()
	g := gin.New()
	g.Use(recordRequest(m))
	g.GET("/ok", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/ok", nil)
	g.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)

	out := scrape(t, m)
	assert.Contains(t, out, `ezoidc_requests_total{endpoint="/ok",status="200"} 1`)
}

func scrape(t *testing.T, m *Metrics) string {
	g := NewMetricsAPI(m)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	g.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	return w.Body.String()
}
