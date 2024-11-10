package models

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-jose/go-jose/v4"
	"github.com/rs/zerolog/log"
)

type Issuer struct {
	// The name of the issuer to be used in the policy
	Name string `json:"name"`
	// The issuer's URL
	Issuer string `json:"issuer"`
	// The URI to obtain the JWKS from
	JWKSURI string `json:"jwks_uri,omitempty" yaml:"jwks_uri,omitempty"`
	// The content of the JWKS
	JWKS *JWKS `json:"jwks,omitempty"`
}

// Attempt to resolve the issuer's JWKS using OIDC Discovery or the provided JWKS URI
func (i *Issuer) LoadJWKS(ctx context.Context, client *http.Client) error {
	if i.JWKSURI == "" && i.JWKS == nil {
		resp, err := client.Get(i.Issuer + "/.well-known/openid-configuration")
		if err != nil {
			return fmt.Errorf("failed to get openid-configuration for issuer %s: %w", i.Issuer, err)
		}
		defer resp.Body.Close()

		var oidcConfig struct {
			JwksUri string `json:"jwks_uri"`
		}
		err = json.NewDecoder(resp.Body).Decode(&oidcConfig)
		if err != nil {
			return fmt.Errorf("failed to decode openid-configuration for issuer %s: %w", i.Issuer, err)
		}
		i.JWKSURI = oidcConfig.JwksUri

		log.Debug().Str("issuer", i.Issuer).Str("jwks_uri", i.JWKSURI).Msg("discovered jwks_uri of issuer")
	}

	if i.JWKS != nil {
		return nil
	}

	resp, err := client.Get(i.JWKSURI)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("jwks uri %s returned status code %d", i.JWKSURI, resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	err = json.NewDecoder(resp.Body).Decode(&jwks)
	if err != nil {
		return fmt.Errorf("failed to decode jwks as json: %w", err)
	}

	if len(jwks.Keys) == 0 {
		return fmt.Errorf("jwks uri %s returned no keys", i.JWKSURI)
	}

	i.JWKS = &JWKS{jwks.Keys}
	log.Debug().Str("issuer", i.Issuer).Int("keys", len(i.JWKS.Keys)).Msg("loaded jwks of issuer")

	return nil
}
