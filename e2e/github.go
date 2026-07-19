package main

import (
	"context"
	"dagger/e-2-e/internal/dagger"
	"encoding/json"

	"github.com/stretchr/testify/assert"
)

func (m *E2E) TestGithub(ctx context.Context) error {
	if m.githubToken == nil {
		return nil
	}

	token, _ := m.githubToken.Plaintext(ctx)
	if token == "" {
		return nil
	}

	config := Configuration{
		Audience: "http://ezoidc:3501",
		Listen:   "0.0.0.0:3501",
		Policy: `
			allow.read("success") if {
				issuer = "github"
				startswith(subject, "repo:ezoidc/ezoidc:ref:refs/heads/")
				claims.event_name in {"workflow_dispatch", "push"}
				claims.ref_type = "branch"
				claims.repository_owner = "ezoidc"
				claims.repository_visibility = "public"
				claims.runner_environment = "github-hosted"
				claims.workflow = "E2E"
				claims.workflow_ref = claims.job_workflow_ref
				startswith(claims.workflow_ref, "ezoidc/ezoidc/.github/workflows/e2e.yml@refs/heads/")
			}
		`,
		Variables: map[string]any{
			"success": map[string]any{
				"value": "true",
			},
		},
		Issuers: map[string]any{
			"github": map[string]any{
				"issuer": "https://token.actions.githubusercontent.com",
			},
		},
		LogLevel: "debug",
	}

	server := dag.Container().
		From(baseImage).
		WithMountedFile("/bin/ezoidc-server", m.EzoidcServer).
		WithNewFile("/config.yaml", config.MarshalYAML()).
		WithExposedPort(3501).
		AsService(dagger.ContainerAsServiceOpts{
			Args: []string{"/bin/ezoidc-server", "start", "/config.yaml"},
		})

	output, err := dag.Container().
		From(baseImage).
		WithServiceBinding("ezoidc", server).
		WithMountedFile("/bin/ezoidc", m.Ezoidc).
		WithSecretVariable("EZOIDC_TOKEN", m.githubToken).
		With(cacheBuster).
		WithExec([]string{"/bin/ezoidc", "variables", "json"}).
		Stdout(ctx)
	assert.NoError(t, err)

	variables := &Variables{}
	err = json.Unmarshal([]byte(output), variables)
	assert.NoError(t, err)

	values := variables.Values()

	assert.Equal(t, "true", values["success"])

	return nil
}
