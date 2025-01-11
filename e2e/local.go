package main

import (
	"context"
	"dagger/e-2-e/internal/dagger"
	"encoding/json"
	"time"

	"github.com/stretchr/testify/assert"
)

func (m *E2E) TestLocal(ctx context.Context) error {
	issuer := NewIssuer()
	config := Configuration{
		Audience: "http://ezoidc:3501",
		Listen:   "0.0.0.0:3501",
		Policy:   `allow.read(_)`,
		Variables: map[string]any{
			"str": map[string]any{
				"value": "str",
			},
			"env": map[string]any{
				"value": map[string]any{
					"env": "ENV_VAR",
				},
				"redact": true,
			},
			"file": map[string]any{
				"value": map[string]any{
					"file": "/file.txt",
				},
			},
		},
		Issuers: map[string]any{
			"dagger": map[string]any{
				"issuer": "http://localhost:3000",
				"jwks":   issuer.MarshalJWKS(),
			},
		},
	}

	server := dag.Container().
		From(baseImage).
		WithMountedFile("/bin/ezoidc-server", m.EzoidcServer).
		WithNewFile("/config.yaml", config.MarshalYAML()).
		WithEnvVariable("ENV_VAR", "value").
		WithNewFile("/file.txt", "content").
		WithExposedPort(3501).
		AsService(dagger.ContainerAsServiceOpts{
			Args: []string{"/bin/ezoidc-server", "start", "/config.yaml"},
		})

	output, err := dag.Container().
		From(baseImage).
		WithServiceBinding("ezoidc", server).
		WithMountedFile("/bin/ezoidc", m.Ezoidc).
		WithEnvVariable("EZOIDC_TOKEN", issuer.SignToken(map[string]any{
			"iss": "http://localhost:3000",
			"aud": []string{"http://ezoidc:3501"},
			"sub": "foo",
		})).
		WithEnvVariable("CACHE", time.Now().String()).
		WithExec([]string{"/bin/ezoidc", "variables", "json"}).
		Stdout(ctx)
	assert.NoError(t, err)

	variables := &Variables{}
	_ = json.Unmarshal([]byte(output), variables)

	assert.Equal(t, map[string]string{
		"str":  "str",
		"env":  "value",
		"file": "content",
	}, variables.Values())

	return nil
}
