# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=controller-role crd webhook paths="./api/v1alpha1" paths="./internal/controller" output:crd:artifacts:config=charts/runtime-enforcer/templates/crd output:rbac:artifacts:config=charts/runtime-enforcer/templates/controller output:webhook:none
	$(CONTROLLER_GEN) rbac:roleName=agent-role paths="./cmd/agent" paths="./internal/eventhandler" paths="./internal/workloadpolicyhandler" output:rbac:artifacts:config=charts/runtime-enforcer/templates/agent
	$(CONTROLLER_GEN) rbac:roleName=debugger-role paths="./cmd/debugger" output:rbac:artifacts:config=charts/runtime-enforcer/templates/debugger
	sed -i 's/controller-role/{{ include "runtime-enforcer.fullname" . }}-controller/' charts/runtime-enforcer/templates/controller/role.yaml
	sed -i 's/agent-role/{{ include "runtime-enforcer.fullname" . }}-agent/' charts/runtime-enforcer/templates/agent/role.yaml
	sed -i 's/debugger-role/{{ include "runtime-enforcer.fullname" . }}-debugger/' charts/runtime-enforcer/templates/debugger/role.yaml

REPO ?= ghcr.io/kubewarden/runtime-enforcer
TAG ?= latest

define BUILD_template =
.PHONY: build-$(1)-image
build-$(1)-image: generate-ebpf vet
	docker buildx build -f package/Dockerfile.$(1) \
	-t "$(REPO)/$(1):$(TAG)" --load .
	@echo "Built $(REPO)/$(1):$(TAG)"

E2E_DEPS += build-$(1)-image
endef

TARGET=controller agent debugger
$(foreach T,$(TARGET),$(eval $(call BUILD_template,$(T))))

.PHONY: generate
generate: manifests generate-ebpf generate-proto generate-api generate-crd-docs generate-chart generate-kubectl-plugin-docs
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: generate-ebpf
generate-ebpf: ## Generate eBPF artifacts.
	go generate ./internal/bpf

.PHONY: generate-crd-docs
generate-crd-docs: ## Generate CRD documentation.
	make -C docs/crds asciidoc

.PHONY: generate-kubectl-plugin-docs
generate-kubectl-plugin-docs: ## Generate kubectl plugin docs.
	go run ./internal/tools/docgen -out docs/kubectl-plugin

.PHONY: test
test: generate-ebpf vet setup-envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)"    go test $$(go list ./... | grep -v /e2e | grep -v /internal/bpf) -race -test.v -coverprofile coverage/cover.out -covermode=atomic

.PHONY: helm-unittest
helm-unittest:
	helm unittest charts/runtime-enforcer/ --file "tests/**/*_test.yaml"

.PHONY: test-e2e
test-e2e: kubectl-plugin
ifneq ($(E2E_USE_EXISTING_CLUSTER),true)
ifeq ($(E2E_NO_REBUILD),)
	TAG=latest make $(E2E_DEPS)
endif
endif
	E2E_USE_EXISTING_CLUSTER=$(E2E_USE_EXISTING_CLUSTER) E2E_DEPENDENCIES=$(E2E_DEPENDENCIES) go test -v -timeout 20m ./test/e2e/ 

##@ Build

.PHONY: controller
controller: generate-ebpf fmt ## Build manager binary.
	CGO_ENABLED=0 GOOS=linux go build -o bin/controller ./cmd/controller

.PHONY: test-bpf
test-bpf: generate-ebpf ## Run bpf tests.
	go test -v ./internal/bpf -count=1 -exec "sudo -E"

.PHONY: check-nri-benchmarks
check-nri-benchmarks: generate-ebpf ## Validate NRI callback benchmarks against thresholds.
	hack/ci/check-nri-benchmarks.sh

.PHONY: agent
agent: generate-ebpf fmt ## Build agent binary.
	CGO_ENABLED=0 GOOS=linux go build -o bin/agent ./cmd/agent

# Version for kubectl plugin (git describe or "dev")
KUBECTL_PLUGIN_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Platforms for cross-compilation of the kubectl plugin
PLUGIN_PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

.PHONY: kubectl-plugin
kubectl-plugin: ## Build kubectl plugin for the current platform.
	go build -ldflags "-X github.com/kubewarden/runtime-enforcer/internal/kubectlplugin.version=$(KUBECTL_PLUGIN_VERSION)" -o ./bin/kubectl-runtime_enforcer ./cmd/kubectl-plugin

.PHONY: kubectl-plugin-cross
kubectl-plugin-cross: ## Build kubectl plugin for all target platforms.
	@mkdir -p bin/kubectl-plugin
	@for platform in $(PLUGIN_PLATFORMS); do \
		os=$$(echo $$platform | cut -d/ -f1); \
		arch=$$(echo $$platform | cut -d/ -f2); \
		out=bin/kubectl-plugin/kubectl-runtime_enforcer-$$os-$$arch; \
		echo "Building $$out ..."; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build \
			-ldflags "-X github.com/kubewarden/runtime-enforcer/internal/kubectlplugin.version=$(KUBECTL_PLUGIN_VERSION)" \
			-o $$out \
			./cmd/kubectl-plugin; \
	done
	@echo "Cross-build complete. Artifacts in bin/kubectl-plugin/"

.PHONY: debugger
debugger: generate-ebpf fmt ## Build debugger binary.
	CGO_ENABLED=0 GOOS=linux go build -o bin/debugger ./cmd/debugger

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/controller/main.go

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
PROTOC_GEN_GO ?= $(LOCALBIN)/protoc-gen-go
PROTOC_GEN_GO_GRPC ?= $(LOCALBIN)/protoc-gen-go-grpc
HELM_VALUES_SCHEMA_JSON ?= $(LOCALBIN)/helm-values-schema-json

## Tool Versions
CONTROLLER_TOOLS_VERSION ?= v0.17.1
#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= $(shell go list -m -f "{{ .Version }}" sigs.k8s.io/controller-runtime | awk -F'[v.]' '{printf "release-%d.%d", $$2, $$3}')
#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= $(shell go list -m -f "{{ .Version }}" k8s.io/api | awk -F'[v.]' '{printf "1.%d", $$3}')
HELM_VALUES_SCHEMA_JSON_VERSION ?= v2.3.1
PROTOC_GEN_GO_VERSION ?= v1.36.11
PROTOC_GEN_GO_GRPC_VERSION ?= v1.6.1

.PHONY: tools
tools: controller-gen envtest protoc-gen-go protoc-gen-go-grpc helm-values-schema-json

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@$(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: protoc-gen-go
protoc-gen-go: $(PROTOC_GEN_GO)
$(PROTOC_GEN_GO): | $(LOCALBIN)
	$(call go-install-tool,$(PROTOC_GEN_GO),google.golang.org/protobuf/cmd/protoc-gen-go,$(PROTOC_GEN_GO_VERSION))

.PHONY: protoc-gen-go-grpc
protoc-gen-go-grpc: $(PROTOC_GEN_GO_GRPC)
$(PROTOC_GEN_GO_GRPC): | $(LOCALBIN)
	$(call go-install-tool,$(PROTOC_GEN_GO_GRPC),google.golang.org/grpc/cmd/protoc-gen-go-grpc,$(PROTOC_GEN_GO_GRPC_VERSION))

.PHONY: generate-proto
generate-proto: $(PROTOC_GEN_GO) $(PROTOC_GEN_GO_GRPC)
	PATH=$(LOCALBIN):$(PATH) protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./proto/agent/v1/agent.proto

.PHONY: generate-api
generate-api:
	go install ./hack/tools.go
	API_KNOWN_VIOLATIONS_DIR=. UPDATE_API_KNOWN_VIOLATIONS=true ./hack/update-codegen.sh

.PHONY: helm-values-schema-json
helm-values-schema-json: $(HELM_VALUES_SCHEMA_JSON)
$(HELM_VALUES_SCHEMA_JSON): | $(LOCALBIN)
	$(call go-install-tool,$(HELM_VALUES_SCHEMA_JSON),github.com/losisin/helm-values-schema-json/v2,$(HELM_VALUES_SCHEMA_JSON_VERSION))

.PHONY: generate-chart
generate-chart: $(HELM_VALUES_SCHEMA_JSON) ## Generate Helm chart values schema.
	$(HELM_VALUES_SCHEMA_JSON) --no-additional-properties --values charts/runtime-enforcer/values.yaml --output charts/runtime-enforcer/values.schema.json

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(1)-$(3) $(1)
endef
