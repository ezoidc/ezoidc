package providers

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/rs/zerolog/log"
)

type SSMProvider struct {
	Client SSMClient
}

type SSMClient interface {
	GetParameters(ctx context.Context, params *ssm.GetParametersInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersOutput, error)
}

func NewSSMProvider() *SSMProvider {
	return &SSMProvider{}
}

var (
	true_     = true
	batchSize = 10
)

func (p *SSMProvider) Read(ctx context.Context, variables map[string]string) (map[string]string, error) {
	err := p.configure(ctx)
	if err != nil {
		return nil, err
	}
	params := []string{}
	paramNames := map[string][]string{}
	for name, param := range variables {
		params = append(params, param)
		paramNames[param] = append(paramNames[param], name)
	}

	result := map[string]string{}
	for i := 0; i < len(params); i += batchSize {
		end := i + batchSize
		if end > len(params) {
			end = len(params)
		}
		log.Debug().Int("parameters", len(params[i:end])).Msg("get ssm parameters")
		resp, err := p.Client.GetParameters(ctx, &ssm.GetParametersInput{
			Names:          params[i:end],
			WithDecryption: &true_,
		})
		if err != nil {
			log.Warn().Err(err).Msg("failed to get ssm parameters")
			continue
		}
		if len(resp.InvalidParameters) > 0 {
			log.Warn().Any("parameters", resp.InvalidParameters).Msg("invalid ssm parameters")
		}
		for _, param := range resp.Parameters {
			if param.Name != nil && param.Value != nil {
				for _, name := range paramNames[*param.Name] {
					result[name] = *param.Value
				}
			}
		}
	}

	return result, nil
}

func (p *SSMProvider) configure(ctx context.Context) error {
	if p.Client != nil {
		return nil
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	p.Client = ssm.NewFromConfig(cfg)
	return nil
}
