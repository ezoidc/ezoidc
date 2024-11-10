package providers

import (
	"context"
	"fmt"

	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/ezoidc/ezoidc/pkg/models"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func init() {
	log.Logger = zerolog.Nop()
}

type MockProvider struct{}

func (p *MockProvider) Read(ctx context.Context, variables map[string]string) (map[string]string, error) {
	values := map[string]string{
		"key": "value",
	}

	output := map[string]string{}
	for name, value := range values {
		output[name] = value
	}

	return output, nil
}

type MockSSMClient struct{}

func (c *MockSSMClient) GetParameters(ctx context.Context, params *ssm.GetParametersInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersOutput, error) {
	var key = "ssmParamName"
	var value = "ssmValue"

	return &ssm.GetParametersOutput{
		Parameters: []types.Parameter{
			{
				Name:  &key,
				Value: &value,
			},
		},
	}, nil
}

type MockKubernetesClient struct{}

func (c *MockKubernetesClient) GetSecret(ctx context.Context, namespace string, name string) (map[string][]byte, error) {
	secrets := map[string]map[string]map[string][]byte{
		"default": {
			"secret": {
				".secret": []byte("defaultvalue"),
			},
		},
		"namespace": {
			"secret": {
				".secret": []byte("namespacevalue"),
			},
		},
	}
	if _, ok := secrets[namespace]; !ok {
		return nil, fmt.Errorf("namespace not found")
	}
	if _, ok := secrets[namespace][name]; !ok {
		return nil, fmt.Errorf("secret not found")
	}
	return secrets[namespace][name], nil
}

func TestResolverDefault(t *testing.T) {
	r := NewResolver()
	r.WithDefaultProviders()
	r.Add("aws.ssm", &SSMProvider{
		Client: &MockSSMClient{},
	})
	r.Add("kubernetes.secret", &KubernetesSecretsProvider{
		Client:    &MockKubernetesClient{},
		Namespace: "default",
	})

	envId := "envvar"
	os.Setenv(envId, "value")
	defer os.Unsetenv(envId)

	variables := []models.Variable{
		{
			Name: "key",
			Value: models.VariableValue{
				Provider: "string",
				ID:       "literalstring",
			},
		},
		{
			Name: "env",
			Value: models.VariableValue{
				Provider: "env",
				ID:       envId,
			},
		},
		{
			Name: "file",
			Value: models.VariableValue{
				Provider: "file",
				ID:       "testdata/file.txt",
			},
		},
		{
			Name: "ssm",
			Value: models.VariableValue{
				Provider: "aws.ssm",
				ID:       "ssmParamName",
			},
		},
		{
			Name: "ssm2",
			Value: models.VariableValue{
				Provider: "aws.ssm",
				ID:       "ssmParamName",
			},
		},
		{
			Name: "k8s-default",
			Value: models.VariableValue{
				Provider: "kubernetes.secret",
				ID:       "secret/.secret",
			},
		},
		{
			Name: "k8s-namespace",
			Value: models.VariableValue{
				Provider: "kubernetes.secret",
				ID:       "namespace/secret/.secret",
			},
		},
		{
			Name: "k8s-notfound",
			Value: models.VariableValue{
				Provider: "kubernetes.secret",
				ID:       "namespace/notfound/.secret",
			},
		},
		{
			Name: "k8s-notfoundprop",
			Value: models.VariableValue{
				Provider: "kubernetes.secret",
				ID:       "namespace/secret/.notfound",
			},
		},
	}

	output, err := r.Resolve(context.TODO(), variables)
	assert.NoError(t, err)

	assert.ElementsMatch(t, []models.Variable{
		{
			Name: "key",
			Value: models.VariableValue{
				String: "literalstring",
			},
		},
		{
			Name: "env",
			Value: models.VariableValue{
				String: "value",
			},
		},
		{
			Name: "file",
			Value: models.VariableValue{
				String: "file content",
			},
		},
		{
			Name: "ssm",
			Value: models.VariableValue{
				String: "ssmValue",
			},
		},
		{
			Name: "ssm2",
			Value: models.VariableValue{
				String: "ssmValue",
			},
		},
		{
			Name: "k8s-default",
			Value: models.VariableValue{
				String: "defaultvalue",
			},
		},
		{
			Name: "k8s-namespace",
			Value: models.VariableValue{
				String: "namespacevalue",
			},
		},
		{
			Name:  "k8s-notfoundprop",
			Value: models.VariableValue{},
		},
	}, output)

	for _, v := range variables {
		assert.Equal(t, v.Value.String, "")
	}
}

func TestResolverCustom(t *testing.T) {
	r := NewResolver()
	r.Add("mock", &MockProvider{})

	variables := []models.Variable{
		{
			Name: "key",
			Value: models.VariableValue{
				Provider: "mock",
				ID:       "key",
			},
		},
		{
			Name: "notfound",
			Value: models.VariableValue{
				Provider: "mock",
				ID:       "notfound",
			},
		},
	}

	output, err := r.Resolve(context.TODO(), variables)
	assert.NoError(t, err)

	assert.ElementsMatch(t, []models.Variable{
		{
			Name: "key",
			Value: models.VariableValue{
				String: "value",
			},
		},
	}, output)
}
