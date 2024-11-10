package providers

import (
	"context"

	"github.com/ezoidc/ezoidc/pkg/models"
	"github.com/rs/zerolog/log"
)

type VariableProvider interface {
	Read(ctx context.Context, variables map[string]string) (map[string]string, error)
}

type Resolver struct {
	providers map[string]VariableProvider
}

func NewResolver() *Resolver {
	return &Resolver{
		providers: map[string]VariableProvider{},
	}
}

func (r *Resolver) WithDefaultProviders() *Resolver {
	r.Add("env", NewEnvProvider())
	r.Add("string", NewStringProvider())
	r.Add("file", NewFileProvider())
	r.Add("aws.ssm", NewSSMProvider())
	r.Add("kubernetes.secret", NewKubernetesProvider())
	return r
}

func (r *Resolver) Add(id string, provider VariableProvider) {
	r.providers[id] = provider
}

func (r *Resolver) ForVariable(v models.Variable) (VariableProvider, string) {
	return r.providers[v.Value.Provider], v.Value.ID
}

func (r *Resolver) Resolve(ctx context.Context, variables []models.Variable) ([]models.Variable, error) {
	byProvider := map[VariableProvider]map[string]string{}
	byName := map[string]models.Variable{}

	for _, v := range variables {
		provider, id := r.ForVariable(v)
		if provider == nil {
			log.Warn().
				Str("provider", v.Value.Provider).
				Str("id", v.Value.ID).
				Msg("unknown variable provider")
			continue
		}

		if byProvider[provider] == nil {
			byProvider[provider] = map[string]string{}
		}

		byProvider[provider][v.Name] = id
		byName[v.Name] = v
	}

	resolved := make([]models.Variable, 0, len(variables))
	for provider, kv := range byProvider {
		if provider == nil || len(kv) == 0 {
			continue
		}

		values, err := provider.Read(ctx, kv)
		if err != nil {
			return nil, err
		}

		for name, value := range values {
			resolved = append(resolved, byName[name].Resolve(value))
		}
	}

	return resolved, nil
}
