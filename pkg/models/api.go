package models

type MetadataResponse struct {
	Ezoidc     bool   `json:"ezoidc"`
	APIVersion string `json:"api_version"`
}

type VariablesResponse struct {
	Variables []Variable `json:"variables"`
}

type ErrorResponse struct {
	Error  string `json:"error"`
	Reason string `json:"reason,omitempty"`
}
