package providers

import (
	"context"
	"os"

	"github.com/rs/zerolog/log"
)

type EnvProvider struct {
	GetEnv func(string) string
}

func NewEnvProvider() *EnvProvider {
	return &EnvProvider{
		GetEnv: os.Getenv,
	}
}

func (p *EnvProvider) Read(ctx context.Context, variables map[string]string) (map[string]string, error) {
	result := make(map[string]string)
	for k, v := range variables {
		result[k] = p.GetEnv(v)

		if result[k] == "" {
			log.Warn().Str("variable", k).Str("env", v).Msg("env variable is empty")
		}
	}
	return result, nil
}
