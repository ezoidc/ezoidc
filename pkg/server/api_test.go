package server

import (
	"bytes"
	"context"
	"time"

	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ezoidc/ezoidc/pkg/engine"
	"github.com/ezoidc/ezoidc/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func init() {
	log.Logger = zerolog.Nop()
}

func TestGetMetadata(t *testing.T) {
	ctx := context.TODO()
	e := engine.NewEngine(nil)
	api := NewAPI(e)
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, "GET", "/ezoidc/", nil)
	api.Gin.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Equal(t, `{"ezoidc":true,"api_version":"1.0"}`, w.Body.String())
}

func TestReadVariables(t *testing.T) {
	ctx := context.TODO()
	issuer := "http://mock"
	audience := "http://ezoidc"
	cfg := &models.Configuration{
		Audience: []string{audience},
		Issuers: map[string]*models.Issuer{
			"mock": {
				Name:   "mock",
				Issuer: issuer,
				JWKS:   &models.JWKS{Keys: jwks.Keys},
			},
		},
		Algorithms: []jose.SignatureAlgorithm{"RS256"},
		Policy: `
			allow.read("public") if not params.name
			allow.read("param") if params.name = "param"
		`,
		Variables: models.Variables{
			{
				Name: "public",
				Value: models.VariableValue{
					Provider: "string",
					ID:       "123",
				},
			},
			{
				Name: "param",
				Value: models.VariableValue{
					Provider: "string",
					ID:       "value",
				},
			},
		},
	}
	cases := map[string]struct {
		claims   map[string]any
		params   map[string]any
		code     int
		request  string
		response string
	}{
		"success": {
			claims: map[string]any{
				"iss": issuer,
				"aud": audience,
				"exp": time.Now().Add(time.Minute).Unix(),
			},
			code:     200,
			request:  `{}`,
			response: `{"variables":[{"name":"public","value":{"string":"123"}}]}`,
		},
		"params": {
			claims: map[string]any{
				"iss": issuer,
				"aud": audience,
				"exp": time.Now().Add(time.Minute).Unix(),
			},
			code:     200,
			request:  `{"params":{"name":"param"}}`,
			response: `{"variables":[{"name":"param","value":{"string":"value"}}]}`,
		},
		"expired": {
			claims: map[string]any{
				"iss": issuer,
				"aud": audience,
				"exp": time.Now().Add(-time.Minute).Unix(),
			},
			code:     401,
			response: `{"error":"go-jose/go-jose/jwt: validation failed, token is expired (exp)","reason":"invalid:claims:exp"}`,
		},
		"invalid json": {
			claims: map[string]any{
				"iss": issuer,
				"aud": audience,
				"exp": time.Now().Add(time.Minute).Unix(),
			},
			code:     400,
			request:  "invalid json",
			response: `{"error":"invalid JSON request body: invalid character 'i' looking for beginning of value"}`,
		},
	}
	e := engine.NewEngine(cfg)
	err := e.Compile(ctx)
	assert.NoError(t, err)
	api := NewAPI(e)

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			token := sign(c.claims)
			req, _ := http.NewRequestWithContext(ctx, "POST", "/ezoidc/1.0/variables", bytes.NewBuffer([]byte(c.request)))
			req.Header.Set("Authorization", "Bearer "+token)
			api.Gin.ServeHTTP(w, req)
			assert.Equal(t, c.code, w.Code)
			assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))
			assert.Equal(t, c.response, w.Body.String())
		})
	}
}

func TestMaxBodySize(t *testing.T) {
	ctx := context.TODO()
	cfg := &models.Configuration{}
	e := engine.NewEngine(cfg)
	api := NewAPI(e)
	api.Gin.POST("/upload", func(ctx *gin.Context) {
		var body string
		err := ctx.ShouldBindBodyWithJSON(&body)
		if err != nil {
			assert.Equal(t, "http: request body too large", err.Error())
			ctx.AbortWithStatus(http.StatusBadRequest)
			return
		}
		ctx.JSON(200, len(body))
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, "POST", "/upload", bytes.NewBuffer([]byte(`"smol"`)))
	api.Gin.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)

	largeBody := bytes.Repeat([]byte("a"), int(MaxBodySize+10))
	w = httptest.NewRecorder()
	req, _ = http.NewRequestWithContext(ctx, "POST", "/upload", bytes.NewBuffer(largeBody))
	api.Gin.ServeHTTP(w, req)
	assert.Equal(t, 400, w.Code)
}
