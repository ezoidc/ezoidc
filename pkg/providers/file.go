package providers

import (
	"context"
	"os"

	"github.com/rs/zerolog/log"
)

type FileProvider struct{}

func NewFileProvider() *FileProvider {
	return &FileProvider{}
}

func (p *FileProvider) Read(ctx context.Context, variables map[string]string) (map[string]string, error) {
	result := make(map[string]string)
	for k, v := range variables {
		content, err := os.ReadFile(v)
		if err != nil {
			log.Warn().Err(err).Str("variable", k).Str("file", v).Msg("failed to read file")
			continue
		}
		result[k] = string(content)
	}
	return result, nil
}
