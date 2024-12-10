package engine

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/ezoidc/ezoidc/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

var true_ = true

func TestCompile(t *testing.T) {
	ctx := context.TODO()
	cfg := &models.Configuration{
		Policy: `allow.read("foo")`,
	}
	e := NewEngine(cfg)
	err := e.Compile(ctx)
	assert.NoError(t, err)
}

func TestAllowedVariables(t *testing.T) {
	ctx := context.TODO()
	cfg := &models.Configuration{
		Policy: `
			allow.read("var")
			allow.internal(_)
			define.var.value = "foo"
			define.internal.value = "internal"
		`,
	}
	e := NewEngine(cfg)
	err := e.Compile(ctx)
	assert.NoError(t, err)

	allowed, err := e.AllowedVariables(ctx, nil)
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{
		"var":      "read",
		"internal": "internal",
	}, allowed)
}

func TestReadVariables(t *testing.T) {
	cfg := &models.Configuration{
		Policy: `
			allow.read(name) if {
				name in {"allowed", "defined"}
				issuer = "test"
				subject = "read"
				claims.iss = "http://test"
				claims.custom = true
				params.id = 123
			}
			define.defined.value = "foo"
			define.defined_not_allowed.value = "no"
		`,
		Variables: []models.Variable{
			{Name: "not-allowed", Value: models.VariableValue{Provider: "string", ID: "asdf"}},
			{Name: "allowed", Value: models.VariableValue{Provider: "string", ID: "bar"}, Redact: &true_},
		},
		Issuers: map[string]*models.Issuer{
			"test": {
				Issuer: "http://test",
			},
		},
	}
	e := NewEngine(cfg)
	ctx := context.TODO()
	err := e.Compile(ctx)
	assert.NoError(t, err)

	output, err := e.ReadVariables(ctx, &ReadRequest{
		Claims: map[string]any{
			"iss":    "http://test",
			"sub":    "read",
			"custom": true,
		},
		Params: map[string]any{
			"id": 123,
		},
	})
	assert.NoError(t, err)

	assert.ElementsMatch(t, []models.Variable{
		{Name: "allowed", Value: models.VariableValue{String: "bar"}, Redact: &true_},
		{Name: "defined", Value: models.VariableValue{String: "foo"}},
	}, output.Variables)
}

func TestReadInternal(t *testing.T) {
	ctx := context.TODO()
	cfg := &models.Configuration{
		Policy: `
			allow.read("defined")

			allow.internal(name) if startswith(name, "internal/")

			define.defined.value = read("internal/key")
			define.private.value = "not allowed"
		`,
		Variables: []models.Variable{
			{Name: "internal/key", Value: models.VariableValue{Provider: "string", ID: "internal"}},
		},
	}
	e := NewEngine(cfg)
	err := e.Compile(ctx)
	assert.NoError(t, err)

	output, err := e.ReadVariables(ctx, nil)
	assert.NoError(t, err)

	assert.ElementsMatch(t, []models.Variable{
		{Name: "defined", Value: models.VariableValue{String: "internal"}},
	}, output.Variables)
}

func TestReadEnv(t *testing.T) {
	ctx := context.TODO()
	envVar := "ENV_VAR_VALUE"
	os.Setenv(envVar, "value")
	defer os.Unsetenv("envvar")

	cfg := &models.Configuration{
		Policy: `allow.read("envvar")`,
		Variables: []models.Variable{
			{Name: "envvar", Value: models.VariableValue{Provider: "env", ID: envVar}},
		},
	}
	e := NewEngine(cfg)

	err := e.Compile(ctx)
	assert.NoError(t, err)

	output, err := e.ReadVariables(ctx, nil)
	assert.NoError(t, err)

	assert.ElementsMatch(t, []models.Variable{
		{Name: "envvar", Value: models.VariableValue{String: "value"}},
	}, output.Variables)
}

func TestReadDynamicExport(t *testing.T) {
	ctx := context.TODO()
	cfg := &models.Configuration{
		Policy: `
			allow.read(_)
			variables[var].export = env if {
				some var in {"env", "id"}
				env := concat("_", ["TF", "VAR", var])
			}
		`,
		Variables: []models.Variable{
			{Name: "env", Value: models.VariableValue{Provider: "string", ID: "build"}},
			{Name: "id", Value: models.VariableValue{Provider: "string", ID: "123"}},
		},
	}
	e := NewEngine(cfg)
	err := e.Compile(ctx)
	assert.NoError(t, err)

	output, err := e.ReadVariables(ctx, nil)
	assert.NoError(t, err)

	assert.ElementsMatch(t, []models.Variable{
		{Name: "env", Value: models.VariableValue{String: "build"}, Export: "TF_VAR_env"},
		{Name: "id", Value: models.VariableValue{String: "123"}, Export: "TF_VAR_id"},
	}, output.Variables)
}

func TestDynamicDefineShouldFail(t *testing.T) {
	ctx := context.TODO()
	cfg := &models.Configuration{
		Policy: `define[name].value = "foo" if some name in {"name"}`,
	}
	e := NewEngine(cfg)
	err := e.Compile(ctx)
	assert.Equal(t, err.Error(), "policy.rego:2: defined variable names must be a scalar")
}

func TestPrintLevels(t *testing.T) {
	ctx := &gin.Context{}
	ctx.Set("request_id", "123")
	cfg := &models.Configuration{
		Policy: `
			allow.read(_)
			define.defaultdebug.value = "foo" if print("msg")
			define.warn.value = "foo" if print("warn: msg")
			define.debug.value = "foo" if print("debug: msg")
			define.error.value = "foo" if print("error: msg")
			define.notalevel.value = "foo" if print("asdf: msg")
		`,
	}
	buf := &bytes.Buffer{}
	log.Logger = zerolog.New(buf)

	e := NewEngine(cfg)
	err := e.Compile(ctx)
	assert.NoError(t, err)

	_, err = e.ReadVariables(ctx, nil)
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), `{"level":"debug","request_id":"123","location":"policy.rego:4","message":"msg"}`)
	assert.Contains(t, buf.String(), `{"level":"warn","request_id":"123","location":"policy.rego:5","message":"msg"}`)
	assert.Contains(t, buf.String(), `{"level":"debug","request_id":"123","location":"policy.rego:6","message":"msg"}`)
	assert.Contains(t, buf.String(), `{"level":"error","request_id":"123","location":"policy.rego:7","message":"msg"}`)
	assert.Contains(t, buf.String(), `{"level":"debug","request_id":"123","location":"policy.rego:8","message":"asdf: msg"}`)

	log.Logger = zerolog.Nop()
}

func TestDuplicateVariables(t *testing.T) {
	ctx := context.TODO()
	cfg := &models.Configuration{
		Policy: `
			allow.read(_)
			define.dupe.value = "define"
		`,
		Variables: []models.Variable{
			{Name: "dupe", Value: models.VariableValue{Provider: "string", ID: "variable"}, Export: "VAR"},
		},
	}
	e := NewEngine(cfg)
	err := e.Compile(ctx)
	assert.NoError(t, err)

	output, err := e.ReadVariables(ctx, nil)
	assert.NoError(t, err)

	assert.ElementsMatch(t, []models.Variable{
		{Name: "dupe", Value: models.VariableValue{String: "define"}, Export: "VAR"},
	}, output.Variables)
}
