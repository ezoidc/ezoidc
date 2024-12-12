# ezoidc
[![Go Reference](https://pkg.go.dev/badge/github.com/ezoidc/ezoidc.svg)](https://pkg.go.dev/github.com/ezoidc/ezoidc) &nbsp;
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE) &nbsp;
[![Build](https://img.shields.io/github/actions/workflow/status/ezoidc/ezoidc/ci.yml?label=CI)](https://github.com/ezoidc/ezoidc/actions/workflows/ci.yml?query=branch%3Amain&label=CI) &nbsp; 
![GitHub Tag](https://img.shields.io/github/v/tag/ezoidc/ezoidc?label=version)


_Policy-based access control for environment variables using federated identities._

> ezoidc is a client-server application that facilitates sharing environment variables with workloads that offer an OpenID Connect (OIDC) identity provider, such as GitHub Actions, GitLab, Kubernetes, and more. Using a policy written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/), the policy language of [Open Policy Agent](https://www.openpolicyagent.org/), ezoidc can be used to implement fine-grained access control and dynamically define variables to generate short-lived, lesser-privileged credentials.

[Documentation](https://docs.ezoidc.dev/)

## Example

This configuration for an ezoidc server deployed at `ezoidc.example.com` allows hosted GitHub Actions runner to access an API key if the workflow is running on the main branch of the repository `org/repo`.

```yaml
policy: |
  allow.read("api_key") if {
    issuer = "github"
    subject = "repo:org/repo:ref:refs/heads/main"
    claims.runner_environment = "github-hosted"
  }

variables:
  api_key:
    value: ak12345
    export: API_KEY

audience: https://ezoidc.example.com

issuers:
  github:
    issuer: https://token.actions.githubusercontent.com
```

In a GitHub Actions workflow, the exported variable `API_KEY` can be loaded using the [`ezoidc/actions/env`](https://github.com/ezoidc/actions) action.

```yaml
jobs:
  build:
    permissions:
      id-token: write
    runs-on: ubuntu-latest
    steps:
      - uses: ezoidc/actions/env@v1
        with:
          audience: https://ezoidc.example.com
      - run: |
          echo "make use of $API_KEY"
```

## Installation

### Go

```sh
go install github.com/ezoidc/ezoidc/cmd/ezoidc@latest
go install github.com/ezoidc/ezoidc/cmd/ezoidc-server@latest
```

### Docker

```sh
docker pull ghcr.io/ezoidc/ezoidc/cli
docker pull ghcr.io/ezoidc/ezoidc/server
```
