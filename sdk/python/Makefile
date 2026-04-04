help: ## Show this help message
help:
	@echo "Available targets:"
	@grep -E '^[a-zA-Z0-9._-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2}' | sort


ci: ## Run all checks
ci: format.check typecheck lint test

test: ## Run unit tests
test:
	uv run python -m unittest discover -s tests

lint: ## Code linting
lint:
	uv run ruff check .

format: ## Code formatting and type checking
format:
	uv run ruff format
	uv run ruff check . --fix

format.check: ## Check if the code is properly formatted
format.check:
	uv run ruff format --check

typecheck: ## Type checking
typecheck:
	uv run ty check

package.build: ## Build the package to distribute
package.build:
	uv build

package.publish: ## Publish the package to PyPI
package.publish:
	uv publish --trusted-publishing always
