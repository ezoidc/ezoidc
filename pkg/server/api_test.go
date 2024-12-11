package server

import (
	"bytes"
	"context"

	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ezoidc/ezoidc/pkg/engine"
	"github.com/ezoidc/ezoidc/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func init() {
	log.Logger = zerolog.Nop()
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
