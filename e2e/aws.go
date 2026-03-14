package main

import (
	"context"
	"dagger/e-2-e/internal/dagger"
	"encoding/json"
	"fmt"
	"time"

	"github.com/stretchr/testify/assert"
)

var localstackImage = "localstack/localstack@sha256:1a27b99734456054146e284d1de44af5d72b9f66a62f8a1fd1e74dc328019ba8"
var baseImage = "alpine:latest@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659"

func (m *E2E) Localstack() *dagger.Service {
	localstackInit := "#!/bin/sh\nset -e\n"
	ssmParams := map[string]struct {
		Name  string
		Value string
		Type  string
	}{
		"param1": {"param1", "value1", "String"},
		"param2": {"param2", "value2", "SecureString"},
		"param3": {"param3", "item1,item2", "StringList"},
	}

	for name, param := range ssmParams {
		localstackInit += fmt.Sprintf(
			"awslocal ssm put-parameter --name %s --value %s --type %s\n",
			name, param.Value, param.Type,
		)
	}

	return dag.Container().
		From(localstackImage).
		WithEnvVariable("DEBUG", "1").
		WithNewFile("/etc/localstack/init/ready.d/ssm.sh", localstackInit, dagger.ContainerWithNewFileOpts{Permissions: 0o755}).
		WithExposedPort(4566).
		AsService(dagger.ContainerAsServiceOpts{
			UseEntrypoint: true,
		})
}

func (m *E2E) TestAws(ctx context.Context) error {
	issuer := NewIssuer()
	config := Configuration{
		Audience: "http://ezoidc:3501",
		Listen:   "0.0.0.0:3501",
		Policy:   `allow.read(_)`,
		Variables: map[string]any{
			"env": map[string]any{
				"value": map[string]any{
					"env": "AWS_SECRET_ACCESS_KEY",
				},
				"redact": true,
			},
			"param1": map[string]any{
				"value": map[string]any{
					"aws.ssm": "param1",
				},
				"redact": false,
			},
			"param2": map[string]any{
				"value": map[string]any{
					"aws.ssm": "param2",
				},
				"export": "PARAM2",
			},
			"param3": map[string]any{
				"value": map[string]any{
					"aws.ssm": "param3",
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

	srv := m.Localstack()
	waitForLocalstack(ctx, srv)

	server := dag.Container().
		From(baseImage).
		WithServiceBinding("localstack", srv).
		WithEnvVariable("AWS_ENDPOINT_URL", "http://localstack:4566").
		WithEnvVariable("AWS_ACCESS_KEY_ID", "000000000000").
		WithEnvVariable("AWS_SECRET_ACCESS_KEY", "ignored").
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
		WithEnvVariable("EZOIDC_TOKEN", issuer.SignToken(map[string]any{
			"iss": "http://localhost:3000",
			"aud": []string{"http://ezoidc:3501"},
			"sub": "foo",
		})).
		WithExec([]string{"/bin/ezoidc", "variables", "json"}).
		Stdout(ctx)
	assert.NoError(t, err)

	variables := &Variables{}
	_ = json.Unmarshal([]byte(output), variables)

	assert.Equal(t, map[string]string{
		"env":    "ignored",
		"param1": "value1",
		"param2": "value2",
		"param3": "item1,item2",
	}, variables.Values())

	assert.Equal(t, map[string]string{
		"param2": "PARAM2",
	}, variables.Exports())

	return nil
}

func waitForLocalstack(ctx context.Context, srv *dagger.Service) error {
	_, err := dag.Container().
		From(localstackImage).
		WithServiceBinding("localstack", srv).
		WithEnvVariable("CACHE", time.Now().String()).
		WithExec([]string{"bash", "-c", `
			while ! curl -s http://localstack:4566/_localstack/init/ready | tee /dev/stderr | grep -q SUCCESSFUL; do
				echo "waiting for localstack..."
				sleep 1
			done
		`}).
		Sync(ctx)

	return err
}
