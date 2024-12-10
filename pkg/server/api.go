package server

import (
	"fmt"

	"github.com/ezoidc/ezoidc/pkg/engine"
	"github.com/ezoidc/ezoidc/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

var APIVersion = "1.0"

type API struct {
	Gin    *gin.Engine
	Engine *engine.Engine
}

func NewAPI(eng *engine.Engine) *API {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(requestID())
	router.Use(jsonLogs())

	public := router.Group("/ezoidc")
	public.GET("/", func(c *gin.Context) {
		c.JSON(200, models.MetadataResponse{
			Ezoidc:     true,
			APIVersion: APIVersion,
		})
	})

	auth := public.Group("/1.0", BearerToken(), ValidToken(eng.Configuration))
	auth.Match([]string{"GET", "POST"}, "/variables", func(c *gin.Context) {
		var body models.VariablesRequest
		if c.Request.Method == "POST" {
			if err := c.ShouldBindJSON(&body); err != nil {
				c.JSON(400, models.ErrorResponse{
					Error: fmt.Sprintf("invalid JSON request body: %s", err.Error()),
				})
				return
			}
		}

		claims := c.GetStringMap("claims")
		response, err := eng.ReadVariables(c, &engine.ReadRequest{
			Claims: claims,
			Params: body.Params,
		})
		if err != nil {
			c.JSON(400, models.ErrorResponse{Error: err.Error()})
			return
		}
		c.Set("allowed", response.Allowed)
		c.JSON(200, models.VariablesResponse{Variables: response.Variables})
	})

	return &API{router, eng}
}

func (a *API) Run() error {
	addr := a.Engine.Configuration.Listen
	log.Info().Str("address", addr).Msg("starting api server")
	return a.Gin.Run(addr)
}

func jsonLogs() gin.HandlerFunc {
	return gin.LoggerWithFormatter(
		func(params gin.LogFormatterParams) string {
			line := log.Info().
				Any("request_id", params.Keys["request_id"]).
				Int("status", params.StatusCode).
				Str("method", params.Method).
				Str("path", params.Path).
				Str("client_ip", params.ClientIP).
				Dur("response_time", params.Latency)

			if allowed, ok := params.Keys["allowed"]; ok {
				line = line.Any("allowed", allowed)
			}

			if issuer, ok := params.Keys["issuer"].(string); ok {
				line = line.Str("issuer", issuer)
			}

			if reason, ok := params.Keys["reason"].(string); ok {
				line = line.Str("reason", reason)
			}

			if claims, ok := params.Keys["claims"].(map[string]interface{}); ok {
				sub, _ := claims["sub"].(string)
				iss, _ := claims["iss"].(string)
				line = line.Str("sub", sub).Str("iss", iss)
			}
			line.Send()
			return ""
		},
	)
}

func requestID() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		rid := uuid.New().String()
		ctx.Set("request_id", rid)
		ctx.Header("X-Request-ID", rid)
	}
}
