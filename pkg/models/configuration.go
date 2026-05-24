package models

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
	"gopkg.in/yaml.v3"
)

var HTTPClient = &http.Client{Timeout: time.Second * 10}

type StringList []string
type Variables []Variable
type JWKS jose.JSONWebKeySet

// Server configuration
type Configuration struct {
	// Rego policy used to control access to variables
	Policy string `json:"policy"`
	// Variables available to the policy
	Variables Variables `json:"variables"`
	// List of audiences to accept
	Audience StringList `json:"audience"`
	// Allowed OIDC issuers
	Issuers map[string]*Issuer `json:"issuers"`
	// Supported JWT token algorithms
	Algorithms []jose.SignatureAlgorithm `json:"algorithms"`
	// IP address and port to listen on
	Listen string `json:"host"`
	// Log level (debug, info, warn, error)
	LogLevel string `yaml:"log_level"`

	issuersByUri map[string]*Issuer
}

// Load a YAML configuration file
func ReadConfiguration(path string) (*Configuration, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	c := Configuration{}
	err = yaml.NewDecoder(f).Decode(&c)
	if err != nil {
		return nil, err
	}

	if len(c.Algorithms) == 0 {
		c.Algorithms = []jose.SignatureAlgorithm{"RS256", "ES256"}
	}

	if c.Issuers == nil {
		c.Issuers = map[string]*Issuer{}
	}

	for name, issuer := range c.Issuers {
		issuer.Name = name
	}

	if len(c.Listen) == 0 {
		port := os.Getenv("PORT")
		if port == "" {
			port = "3501"
		}
		c.Listen = "0.0.0.0:" + port
	}

	if c.LogLevel == "" {
		c.LogLevel = "info"
	}

	return &c, nil
}

// Get issuer by URI
func (c *Configuration) GetIssuer(uri string) *Issuer {
	if c.issuersByUri == nil {
		c.issuersByUri = map[string]*Issuer{}
	}
	iss, ok := c.issuersByUri[uri]
	if !ok {
		for _, i := range c.Issuers {
			if i.Issuer == uri {
				c.issuersByUri[uri] = i
				return i
			}
		}
		c.issuersByUri[uri] = nil
		return nil
	}
	return iss
}

func (c *Configuration) PreloadJWKS(ctx context.Context) error {
	for name, issuer := range c.Issuers {
		issuer.Name = name

		err := issuer.LoadJWKS(ctx, HTTPClient)
		if err != nil {
			return err
		}
	}
	return nil
}

func (o *JWKS) UnmarshalYAML(node *yaml.Node) error {
	var jwks jose.JSONWebKeySet
	switch node.Kind {
	case yaml.ScalarNode:
		err := json.Unmarshal([]byte(node.Value), &jwks)
		if err != nil {
			return fmt.Errorf("failed to unmarshal JWKS: %v", err)
		}
	default:
		return fmt.Errorf("invalid node kind: %v", node.Kind)
	}

	o.Keys = jwks.Keys
	return nil
}

func (o *Variables) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			var variable Variable
			err := node.Content[i+1].Decode(&variable)
			if err != nil {
				if node.Content[i+1].Kind != yaml.ScalarNode {
					return err
				}

				variable.Value.ID = node.Content[i+1].Value
				variable.Value.Provider = "string"
			}
			variable.Name = node.Content[i].Value
			*o = append(*o, variable)
		}
	default:
		return fmt.Errorf("invalid node kind: %v", node.Kind)
	}
	return nil
}

func (s *StringList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		*s = []string{node.Value}
	case yaml.SequenceNode:
		for _, value := range node.Content {
			if value.Kind != yaml.ScalarNode {
				return fmt.Errorf("invalid node kind: %v", value.Kind)
			}
			*s = append(*s, value.Value)
		}
	default:
		return fmt.Errorf("invalid node kind: %v", node.Kind)
	}
	return nil
}
