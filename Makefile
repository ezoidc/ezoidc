TARGETS := ezoidc ezoidc-server
SRC := $(shell find pkg cmd -name '*.go' -not -path '*_test.go')

.DEFAULT_GOAL := default

.PHONY: default build clean format lint test coverage ko.push helm.push test.e2e lint.rego lint.go format.rego format.go

default:
	@echo "Available targets:"
	@awk 'BEGIN { FS = ":" } /^[a-zA-Z0-9_.-]+:/ { if ($$1 !~ /^\./ && $$1 != "default") print "  " $$1 }' $(MAKEFILE_LIST) | sort -u

build: $(TARGETS)

clean:
	rm $(TARGETS)

ezoidc: $(SRC)
	go build ./cmd/ezoidc

ezoidc-server: $(SRC)
	go build ./cmd/ezoidc-server

format: format.go format.rego

format.go:
	go fmt ./...

format.rego:
	opa fmt . -w

lint: lint.go lint.rego

lint.go: golangci-lint ?= golangci-lint
lint.go:
	$(golangci-lint) run --timeout=10m

lint.rego: regal ?= regal
lint.rego:
	$(regal) lint .

test:
	go test ./pkg/... -v

coverage:
	go test ./pkg/... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html

GIT_VERSION = $(shell git tag --points-at)
GIT_COMMIT = $(shell git rev-parse HEAD)
OCI_LABELS = \
	org.opencontainers.image.licenses=Apache-2.0 \
	org.opencontainers.image.authors=ezoidc \
	org.opencontainers.image.source=https://github.com/ezoidc/ezoidc \
	org.opencontainers.image.url=https://github.com/ezoidc/ezoidc \
	org.opencontainers.image.vendor=ezoidc \
	org.opencontainers.image.revision=$(GIT_COMMIT) \
	org.opencontainers.image.version=$(GIT_VERSION)

ko.push:
	ko build -B \
	--sbom "none" \
	$(foreach label,$(OCI_LABELS),--image-annotation $(label) --image-label $(label)) \
	--tags latest$(foreach tag,$(GIT_VERSION),,$(tag)) \
	./ko/server ./ko/cli

helm.push:
	helm package ./chart
	helm push ./chart-*.tgz oci://ghcr.io/ezoidc/ezoidc

test.e2e: only ?=
test.e2e: interactive ?=
test.e2e:
	dagger call $(if $(interactive),-i,) -m e2e build --src . run $(if $(only),--only $(only),)

