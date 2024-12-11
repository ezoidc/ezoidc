package models

import (
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

var true_ = true

func init() {
	log.Logger = zerolog.Nop()
}

func TestReadConfiguration(t *testing.T) {
	jwks := &jose.JSONWebKeySet{}
	_ = json.Unmarshal([]byte(`{"keys":[{"use":"sig","kty":"RSA","kid":"kid","alg":"RS256","n":"AAAA","e":"AQAB"}]}`), jwks)
	cases := []struct {
		path     string
		expected *Configuration
	}{
		{
			path: "empty.yaml",
			expected: &Configuration{
				Listen:     "0.0.0.0:3501",
				Algorithms: []jose.SignatureAlgorithm{"RS256", "ES256"},
				LogLevel:   "info",
				Issuers:    map[string]*Issuer{},
			},
		},
		{
			path: "sample.yaml",
			expected: &Configuration{
				Policy:     "allow.read(_)",
				Listen:     "127.0.0.1:8080",
				Algorithms: []jose.SignatureAlgorithm{"RS256", "ES256"},
				Audience:   []string{"audience1", "audience2"},
				LogLevel:   "warn",
				Variables: []Variable{
					{
						Name: "str",
						Value: VariableValue{
							ID:       "str",
							Provider: "string",
						},
					},
					{
						Name: "strvalue",
						Value: VariableValue{
							ID:       "strvalue",
							Provider: "string",
						},
					},
					{
						Name: "strprovider",
						Value: VariableValue{
							ID:       "strprovider",
							Provider: "string",
						},
					},
					{
						Name: "fromenv",
						Value: VariableValue{
							ID:       "ENV_KEY",
							Provider: "env",
						},
						Redact: &true_,
					},
				},
				Issuers: map[string]*Issuer{
					"selfhosted": {
						Name:    "selfhosted",
						Issuer:  "https://id.example.com",
						JWKSURI: "https://id.example.com/.well-known/openid-configuration/jwks",
					},
					"jwks": {
						Name:   "jwks",
						Issuer: "https://cluster.local",
						JWKS:   &JWKS{jwks.Keys},
					},
				},
			},
		},
	}

	for _, c := range cases {
		actual, err := ReadConfiguration("testdata/" + c.path)
		assert.NoError(t, err)
		assert.Equal(t, c.expected, actual)

		for name, issuer := range actual.Issuers {
			assert.Equal(t, name, issuer.Name)
			assert.Equal(t, actual.GetIssuer(issuer.Issuer), issuer)
			assert.Equal(t, actual.GetIssuer(issuer.Issuer), issuer)
			assert.Nil(t, actual.GetIssuer("n/a"))
		}
	}
}
