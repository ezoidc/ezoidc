package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVariableResolve(t *testing.T) {
	v := Variable{
		Name: "test",
		Value: VariableValue{
			Provider: "env",
			ID:       "foo",
		},
		Export: "TEST",
		Redact: &true_,
	}
	v2 := v.Resolve("bar")

	assert.Equal(t, v.Name, v2.Name)
	assert.Equal(t, v.Export, v2.Export)
	assert.Equal(t, v.Redact, v2.Redact)
	assert.Equal(t, v2.Value, VariableValue{String: "bar"})
}
