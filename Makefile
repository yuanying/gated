# gated
#
# Tests are split by what they need to run. `make test` needs nothing but a Go
# toolchain and is the loop to stay in while developing; everything heavier
# sits behind its own build tag so that `go test ./...` can never pick it up
# (ADR 0007).

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

# Kubernetes version of the control plane binaries envtest runs against.
ENVTEST_K8S_VERSION ?= 1.34.x
# Where setup-envtest keeps the downloaded control plane binaries.
ENVTEST_DIR ?= $(CURDIR)/bin/envtest

GO ?= go
# controller-gen and setup-envtest are pinned by the tool directives in
# go.mod, so every checkout generates byte-identical output.
CONTROLLER_GEN ?= $(GO) tool controller-gen
SETUP_ENVTEST ?= $(GO) tool setup-envtest

##@ General

.PHONY: help
help: ## Show this help.
	@awk 'BEGIN {FS = ":.*##"} \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } \
		/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

##@ Development

.PHONY: generate
generate: ## Regenerate DeepCopy methods and CRD manifests.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./internal/apis/..."
	$(CONTROLLER_GEN) crd paths="./internal/apis/..." output:crd:artifacts:config=config/crd

.PHONY: build
build: ## Build the gated binary into bin/.
	$(GO) build -o bin/gated ./cmd/gated

.PHONY: vet
vet: fmt-check ## Run go vet over every package, including the tagged test packages.
	$(GO) vet ./...
	$(GO) vet -tags envtest ./...
	$(GO) vet -tags integration ./...
	$(GO) vet -tags e2e ./...

.PHONY: fmt
fmt: ## Format the source tree.
	$(GO) fmt ./...

.PHONY: fmt-check
fmt-check: ## Fail if anything in the tree is not gofmt'd.
	@unformatted="$$(gofmt -l . | grep -v '^bin/' || true)"; \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt'd, run \`make fmt\`:"; \
		echo "$$unformatted" | sed 's/^/  /'; \
		exit 1; \
	fi

##@ Test

.PHONY: test
test: ## Run the pure unit tests. No external dependencies, no cluster.
	$(GO) test ./...

.PHONY: envtest-bin
envtest-bin: ## Download the control plane binaries envtest needs.
	@mkdir -p $(ENVTEST_DIR)
	$(SETUP_ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(ENVTEST_DIR) -p path

.PHONY: test-envtest
test-envtest: generate envtest-bin ## Run the CRD tests against a real apiserver and etcd.
	KUBEBUILDER_ASSETS="$$($(SETUP_ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(ENVTEST_DIR) -p path)" \
		$(GO) test -tags envtest -count=1 ./test/envtest/...

.PHONY: test-integration
test-integration: ## Run the tests that need Pebble and a fake identity provider.
	$(GO) test -tags integration -count=1 ./test/integration/...

.PHONY: test-e2e
test-e2e: ## Run the end-to-end tests against a kind cluster.
	$(GO) test -tags e2e -count=1 -timeout 30m ./test/e2e/...

##@ Housekeeping

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum.
	$(GO) mod tidy

.PHONY: clean
clean: ## Remove build and test artifacts.
	rm -rf bin
