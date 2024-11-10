package providers

import (
	"context"
)

type StringProvider struct{}

func NewStringProvider() *StringProvider {
	return &StringProvider{}
}

func (p *StringProvider) Read(ctx context.Context, variables map[string]string) (map[string]string, error) {
	return variables, nil
}
