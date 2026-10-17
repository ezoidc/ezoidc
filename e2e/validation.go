package main

import (
	"context"
	"dagger/e-2-e/internal/dagger"
	_ "embed"
)

//go:embed validation.config.yaml
var validationConfig string

const dexConfig = `
issuer: http://localhost:8080/dex
storage:
  type: memory
web:
  http: 0.0.0.0:5556
enablePasswordDB: true
oauth2:
  passwordConnector: local
  skipApprovalScreen: true
staticClients:
  - id: http://localhost:8080
    name: ezoidc
    secret: ezoidc-secret
    redirectURIs:
      - http://localhost:8080/callback
staticPasswords:
  - email: admin@example.com
    hash: "$2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W"
    username: admin
    userID: "08a8684b-db88-4b73-90a9-3cd1661f5466"
`

const nginxConfig = `
server {
	listen 8080;
	location /ezoidc {
		proxy_pass http://ezoidc:3501;
	}
	location /vm {
		proxy_pass http://victoria-metrics:8428;
	}
	location /dex {
		proxy_pass http://dex:5556;
		proxy_set_header Host $http_host;
	}
}
`

const victoriaMetricsConfig = `
scrape_configs:
  - job_name: ezoidc
    scrape_interval: 5s
    static_configs:
      - targets: ['ezoidc:9999']
`

func (m *E2E) Validation(
	ctx context.Context,
) *dagger.Service {
	dex := dag.Container().
		From("ghcr.io/dexidp/dex:latest@sha256:0ae7ade1bdf1c83f7f7ccb1935912ac4c116e3e8ecc7e7503b30bab77e7c896c").
		WithNewFile("/etc/dex/config.yaml", dexConfig).
		WithExposedPort(5556).
		AsService(dagger.ContainerAsServiceOpts{
			Args: []string{"dex", "serve", "/etc/dex/config.yaml"},
		})

	ezoidcServer := dag.Container().
		From(baseImage).
		WithMountedFile("/bin/ezoidc-server", m.EzoidcServer).
		WithNewFile("/config.yaml", validationConfig).
		WithEnvVariable("ENV_VAR", "value").
		WithNewFile("/file.txt", "content").
		WithServiceBinding("dex", dex).
		WithExposedPort(3501).
		WithExposedPort(9999).
		AsService(dagger.ContainerAsServiceOpts{
			Args: []string{"/bin/ezoidc-server", "start", "/config.yaml"},
		})

	victoriaMetrics := dag.Container().
		From("victoriametrics/victoria-metrics:latest@sha256:4bd592341587d669b7f57d54bbb82bd21ac8675f4e24234b7703a7c0f85197d8").
		WithServiceBinding("ezoidc", ezoidcServer).
		WithNewFile("/scrape.yaml", victoriaMetricsConfig).
		WithExposedPort(8428).
		AsService(dagger.ContainerAsServiceOpts{
			Args: []string{"/victoria-metrics-prod", "-promscrape.config=/scrape.yaml", "-storageDataPath=/tmp/vm", "-http.pathPrefix=/vm"},
		})

	nginx := dag.Container().
		From("nginx:alpine").
		WithServiceBinding("victoria-metrics", victoriaMetrics).
		WithServiceBinding("ezoidc", ezoidcServer).
		WithServiceBinding("dex", dex).
		WithNewFile("/etc/nginx/conf.d/default.conf", nginxConfig).
		WithExposedPort(8080).
		AsService()

	return nginx
}
