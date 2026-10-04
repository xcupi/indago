# Indago — Makefile
# Local-first build & quality gate.

BINARY      := indago
BIN_DIR     := bin
PKG         := ./...
MAIN        := ./cmd/indago
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE        := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(DATE)

.PHONY: all build run test vet fmt fmt-check check tidy clean cover help

all: check build ## Run checks then build

build: ## Build the indago binary into ./bin
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(MAIN)
	@echo "built $(BIN_DIR)/$(BINARY) ($(VERSION))"

run: build ## Build and run `indago serve`
	$(BIN_DIR)/$(BINARY) serve

test: ## Run all tests with the race detector
	go test -race $(PKG)

vet: ## Run go vet
	go vet $(PKG)

fmt: ## Format all Go code
	gofmt -w .

fmt-check: ## Fail if any file is not gofmt-clean
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	@echo "gofmt: clean"

check: fmt-check vet test ## Full quality gate (fmt + vet + test)

tidy: ## Tidy go.mod/go.sum
	go mod tidy

cover: ## Run tests with coverage report
	go test -coverprofile=coverage.txt $(PKG)
	go tool cover -func=coverage.txt | tail -1

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) coverage.txt coverage.html

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS=":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
