package server

import (
	"fmt"
	"net/http"

	"golang.org/x/sync/errgroup"

	"github.com/ezoidc/ezoidc/pkg/engine"
	"github.com/ezoidc/ezoidc/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

var APIVersion = "1.0"
var MaxBodySize int64 = 1024 * 1024 * 5 // 5MB

type API struct {
	Gin     *gin.Engine
	Engine  *engine.Engine
	Metrics *Metrics
}

func NewAPI(eng *engine.Engine) *API {
	metrics := NewMetrics()

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(maxBodySize())
	router.Use(requestID())
	router.Use(jsonLogs())
	router.Use(recordRequest(metrics))

	public := router.Group("/ezoidc")
	public.GET("/", func(c *gin.Context) {
		c.JSON(200, models.MetadataResponse{
			Ezoidc:     true,
			APIVersion: APIVersion,
		})
	})

	auth := public.Group("/1.0", BearerToken(metrics), ValidToken(eng.Configuration, metrics))
	auth.Match([]string{"GET", "POST"}, "/variables", func(c *gin.Context) {
		var body models.VariablesRequest
		if c.Request.Method == "POST" {
			if err := c.ShouldBindJSON(&body); err != nil {
				c.JSON(400, models.ErrorResponse{
					Error: fmt.Sprintf("invalid JSON request body: %s", err.Error()),
				})
				return
			}
			params := []string{}
			for k := range body.Params {
				params = append(params, k)
			}
			c.Set("params", params)
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

		issuer := c.GetString("issuer")
		for name, scope := range response.Allowed {
			metrics.AllowVariable(issuer, name, scope)
		}

		c.JSON(200, models.VariablesResponse{Variables: response.Variables})
	})

	return &API{router, eng, metrics}
}

func (a *API) Run() error {
	server := &http.Server{
		Addr:    a.Engine.Configuration.Listen,
		Handler: a.Gin.Handler(),
	}

	g := &errgroup.Group{}
	g.Go(func() error {
		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	})

	if len(a.Engine.Configuration.MetricsListen) > 0 {
		metricsServer := &http.Server{
			Addr:    a.Engine.Configuration.MetricsListen,
			Handler: NewMetricsAPI(a.Metrics).Handler(),
		}
		g.Go(func() error {
			err := metricsServer.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				return err
			}
			return nil
		})
		log.Info().Str("address", a.Engine.Configuration.MetricsListen).Msg("starting metrics server")
	}

	log.Info().Str("address", a.Engine.Configuration.Listen).Msg("starting api server")
	return g.Wait()
}

// Metrics endpoint serving Prometheus text format
func recordRequest(metrics *Metrics) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		metrics.RequestRate(c.FullPath(), c.Writer.Status())
	}
}

func jsonLogs() gin.HandlerFunc {
	return gin.LoggerWithFormatter(
		func(params gin.LogFormatterParams) (_ string) {
			if params.StatusCode == 404 {
				return
			}

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

			if params, ok := params.Keys["params"].([]string); ok {
				line = line.Strs("params", params)
			}

			line.Send()
			return
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

func maxBodySize() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxBodySize)
		c.Next()
	}
}
