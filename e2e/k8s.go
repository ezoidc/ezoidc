package main

import (
	"context"
	"dagger/e-2-e/internal/dagger"
	"encoding/json"
	"fmt"
	"time"

	"github.com/stretchr/testify/assert"
)

func (m *E2E) TestK8s(ctx context.Context) error {
	if m.dockerSocket == nil {
		return fmt.Errorf("docker socket is required for k8s tests")
	}

	// create a kind cluster outside of dagger
	name := fmt.Sprintf("ezoidc-e2e-%05d", time.Now().UnixNano()%1e8)
	cluster := dag.Kind(m.dockerSocket).Cluster(dagger.KindClusterOpts{
		Name: name,
	})

	_, err := cluster.Create(ctx)
	if err != nil {
		return err
	}
	defer cluster.Delete(ctx)

	kube := dag.Container().From(baseImage).
		WithExec([]string{"apk", "add", "--no-cache", "kubectl", "helm"}).
		WithFile("/usr/bin/ezoidc", m.Ezoidc).
		WithMountedDirectory("/chart", m.HelmChart).
		WithEnvVariable("KUBECONFIG", "/etc/kubeconfig").
		WithFile("/etc/kubeconfig", cluster.Kubeconfig(dagger.KindClusterKubeconfigOpts{
			Internal: true,
		})).
		With(cacheBuster)

	// wait for the node and setup secrets
	kube.WithExec([]string{
		"kubectl", "wait", "--for=condition=Ready", "--timeout=60s", "node/" + name + "-control-plane",
	}).WithExec([]string{
		"kubectl", "create", "secret", "generic", "app-secret",
		"--from-literal=api_key=supersecret",
		"--from-literal=app_id=875439",
	}).Sync(ctx)

	// build the server container
	repository := "ghcr.io/ezoidc/ezoidc/server"
	tag := "e2e"
	serverContainer := dag.Container().
		WithFile("/ezoidc-server", m.EzoidcServer).
		WithEntrypoint([]string{"/ezoidc-server", "start", "--config", "/config.yaml"}).
		WithAnnotation("io.containerd.image.name", repository+":"+tag).
		AsTarball()

	// and load it into the cluster
	cluster.Container().
		WithMountedFile("/server.tar", serverContainer).
		With(cacheBuster).
		WithExec([]string{"kind", "load", "image-archive", "/server.tar"}).
		Sync(ctx)

	// ezoidc-server configuration
	config := Configuration{
		Audience: "http://ezoidc:3501",
		Listen:   "0.0.0.0:3501",
		Policy: `
			allow.read(_)

			define.ezoidc_cluster_token.value = kubernetes_service_account_token({
			  "service_account": "ezoidc",
			})

			define.ezoidc_server_token.value = kubernetes_service_account_token({
			  "service_account": "ezoidc",
			  "audiences": ["http://ezoidc:3501"],
			})
		`,
		Variables: map[string]any{
			"success": map[string]any{
				"value": "true",
			},
			"api_key": map[string]any{
				"value": map[string]any{
					"kubernetes.secret": "app-secret/api_key",
				},
			},
			"app_id": map[string]any{
				"value": map[string]any{
					"kubernetes.secret": "default/app-secret/app_id",
				},
			},
		},
	}

	// install helm chart
	_, err = kube.
		WithNewFile("config.yaml", config.MarshalYAML()).
		WithExec([]string{
			"helm", "upgrade", "--wait", "--install", "ezoidc", "/chart",
			"--set", "image.repository=" + repository,
			"--set", "image.tag=" + tag,
			"--set", "image.pullPolicy=Never",
			"--set", "securityContext.runAsUser=1000",
			"--set-file", "config=config.yaml",
			"--set", "role.namespaceSecrets={app-secret}",
			"--set", "role.serviceAccounts={ezoidc}",
			"--timeout", "1m",
		}).Sync(ctx)
	if err != nil {
		return err
	}

	ezoidcService := kube.WithExposedPort(3501).
		AsService(dagger.ContainerAsServiceOpts{
			Args: []string{"kubectl", "port-forward", "deploy/ezoidc", "3501:3501", "--address", "0.0.0.0"},
		})

	output, err := kube.
		WithServiceBinding("ezoidc", ezoidcService).
		WithExec([]string{"sh", "-ec", `
		  export EZOIDC_TOKEN=$(kubectl create token default --audience http://ezoidc:3501)
			ezoidc variables json
		`}).Stdout(ctx)
	if err != nil {
		return err
	}

	variables := &Variables{}
	err = json.Unmarshal([]byte(output), variables)
	assert.NoError(t, err)

	values := variables.Values()

	assert.Equal(t, "true", values["success"])
	assert.Equal(t, "supersecret", values["api_key"])
	assert.Equal(t, "875439", values["app_id"])
	assert.NotEmpty(t, values["ezoidc_cluster_token"])

	// validate the cluster token by creating a TokenReview
	valid, err := kube.With(kubectlApply(`
kind: TokenReview
apiVersion: authentication.k8s.io/v1
metadata:
  name: test
spec:
  token: ` + values["ezoidc_cluster_token"])).Stdout(ctx)

	assert.Contains(t, valid, `"authenticated": true`)
	assert.Contains(t, valid, `"username": "system:serviceaccount:default:ezoidc"`)

	// test the token against ezoidc-server
	output, err = kube.
		WithServiceBinding("ezoidc", ezoidcService).
		WithEnvVariable("EZOIDC_TOKEN", values["ezoidc_server_token"]).
		WithExec([]string{"ezoidc", "variables", "json"}).
		CombinedOutput(ctx)
	err = json.Unmarshal([]byte(output), variables)
	assert.NoError(t, err)

	values = variables.Values()

	assert.Equal(t, "true", values["success"])

	return err
}

func kubectlApply(config string) func(*dagger.Container) *dagger.Container {
	return func(container *dagger.Container) *dagger.Container {
		return container.WithExec([]string{"kubectl", "apply", "-f", "-", "-o", "json"}, dagger.ContainerWithExecOpts{
			Stdin: config,
		})
	}
}
