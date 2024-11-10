package main

import (
	"context"
	"dagger/e-2-e/internal/dagger"

	"github.com/stretchr/testify/assert"
)

type E2E struct {
	Ezoidc       *dagger.File
	EzoidcServer *dagger.File
}

func (m *E2E) Run(
	ctx context.Context,
	ezoidc *dagger.File,
	ezoidcServer *dagger.File,
	//+default="[]"
	only []string,
) error {
	tests := map[string]bool{}
	m.Ezoidc = ezoidc
	m.EzoidcServer = ezoidcServer

	if len(only) == 0 {
		only = []string{"aws"}
	}

	for _, test := range only {
		tests[test] = true
	}

	if tests["aws"] {
		assert.NoError(t, m.TestAws(ctx), "TestAws")
	}

	return t.Check()
}
