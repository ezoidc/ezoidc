package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ezoidc/ezoidc/pkg/models"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type APIClient struct {
	HTTPClient
	BaseURL string
}

func NewAPIClient(client HTTPClient, baseURL string) *APIClient {
	return &APIClient{
		HTTPClient: client,
		BaseURL:    strings.TrimSuffix(baseURL, "/"),
	}
}

func (c *APIClient) GetVariables(ctx context.Context, r *models.VariablesRequest) (*models.VariablesResponse, error) {
	body, _ := json.Marshal(r)
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/ezoidc/1.0/variables", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+r.Token)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var body models.ErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&body)
		if err != nil {
			return nil, err
		}

		return nil, fmt.Errorf("unexpected status code: %d: %s\n%s", resp.StatusCode, body.Reason, body.Error)
	}
	var variablesResponse models.VariablesResponse
	err = json.NewDecoder(resp.Body).Decode(&variablesResponse)
	if err != nil {
		return nil, err
	}
	return &variablesResponse, nil
}
