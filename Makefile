.DEFAULT_GOAL := help
.PHONY: test race vet lint fmt-check check-vectors ci help

test: ## Run all tests.
	go test ./... -count=1

race: ## Run tests with the race detector.
	go test ./... -race -count=1

vet: ## go vet.
	go vet ./...

lint: ## golangci-lint.
	golangci-lint run ./...

fmt-check: ## Fail when files are not gofmt-formatted.
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "needs gofmt:"; echo "$$out"; exit 1; fi

check-vectors: ## Fail when testdata/vectors.json differs from ../authz-spec.
	@cmp testdata/vectors.json ../authz-spec/vectors.json && echo "vectors in sync"

ci: fmt-check vet lint race ## Everything CI runs.

help: ## List targets.
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'
