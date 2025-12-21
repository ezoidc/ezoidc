package main

import (
	"context"
	"dagger/e-2-e/internal/dagger"

	"github.com/stretchr/testify/assert"
)

var goImage = "golang:1.24.6-alpine@sha256:c8c5f95d64aa79b6547f3b626eb84b16a7ce18a139e3e9ca19a8c078b85ba80d"

type E2E struct {
	Ezoidc       *dagger.File
	EzoidcServer *dagger.File
}

func (m *E2E) Prebuilt(ctx context.Context,
	ezoidc *dagger.File,
	ezoidcServer *dagger.File,
) *E2E {
	m.Ezoidc = ezoidc
	m.EzoidcServer = ezoidcServer
	return m
}

func (m *E2E) Run(
	ctx context.Context,
	//+default="[]"
	only []string,
) (string, error) {
	allTests := map[string]func(context.Context) error{
		"aws":   m.TestAws,
		"local": m.TestLocal,
	}

	if len(only) == 0 {
		for test := range allTests {
			only = append(only, test)
		}
	}

	for _, test := range only {
		assert.NoError(t, allTests[test](ctx), "Test `%s` failed", test)
	}

	if err := t.Check(); err != nil {
		return "", err
	}

	return "✅ No tests failed", nil
}

func (m *E2E) Build(ctx context.Context,
	// +ignore=["*", "!cmd/**", "!pkg/**", "!go.mod", "!go.sum", "**/*_test.go"]
	src *dagger.Directory,
) (*E2E, error) {
	goCache := dag.CacheVolume("go_cache")
	buildCache := dag.CacheVolume("go_build")

	c, err := dag.Container().
		From(goImage).
		WithMountedDirectory("/src", src).
		WithMountedCache("/go/pkg/mod", goCache).
		WithMountedCache("/root/.cache/go-build", buildCache).
		WithWorkdir("/src").
		WithEnvVariable("CGO_ENABLED", "0").
		WithExec([]string{"go", "build", "./cmd/ezoidc"}).
		WithExec([]string{"go", "build", "./cmd/ezoidc-server"}).
		Sync(ctx)
	if err != nil {
		return nil, err
	}

	m.Ezoidc = c.File("ezoidc")
	m.EzoidcServer = c.File("ezoidc-server")
	return m, nil
}
