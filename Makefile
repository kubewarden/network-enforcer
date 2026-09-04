# Image URL to use all building/pushing image targets
IMG ?= controller:latest

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: controller

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

REPO ?= ghcr.io/kubewarden/network-enforcer
TAG ?= latest

define BUILD_template =
.PHONY: build-$(1)-image
build-$(1)-image:
	docker buildx build -f package/Dockerfile.$(1) \
	-t "$(REPO)/$(1):$(TAG)" --load .
	@echo "Built $(REPO)/$(1):$(TAG)"

E2E_DEPS += build-$(1)-image
endef

TARGET=controller
$(foreach T,$(TARGET),$(eval $(call BUILD_template,$(T))))

.PHONY: manifests
manifests: controller-gen ## Generate CRDs and RBAC.
	"$(CONTROLLER_GEN)" crd paths="./api/v1alpha1" \
		output:crd:artifacts:config=charts/network-enforcer/templates/crd
	"$(CONTROLLER_GEN)" rbac:roleName=controller-role paths="./internal/controller" \
		output:rbac:artifacts:config=charts/network-enforcer/templates/controller
	sed -i 's/controller-role/{{ include "network-enforcer.fullname" . }}-controller/' \
		charts/network-enforcer/templates/controller/role.yaml
	# Inject Helm labels after the name line
	sed -i '/^  name:/a\  labels:\n  {{- include "network-enforcer.labels" . | nindent 4 }}' \
		charts/network-enforcer/templates/controller/role.yaml

.PHONY: generate
generate: manifests controller-gen generate-chart-values ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	"$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: fmt vet setup-envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" go test $$(go list ./... | grep -v /e2e) -count=1 -coverprofile cover.out

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	"$(GOLANGCI_LINT)" run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	"$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	"$(GOLANGCI_LINT)" config verify

##@ Build

.PHONY: controller
controller: fmt ## Build controller binary.
	CGO_ENABLED=0 GOOS=linux go build -o bin/controller ./cmd/controller

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name network-enforcer-builder
	$(CONTAINER_TOOL) buildx use network-enforcer-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm network-enforcer-builder
	rm Dockerfile.cross

##@ Deployment

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint
PROTOC_GEN_GO ?= $(LOCALBIN)/protoc-gen-go
PROTOC_GEN_GO_GRPC ?= $(LOCALBIN)/protoc-gen-go-grpc
HELM_VALUES_SCHEMA_JSON ?= $(LOCALBIN)/helm-values-schema-json

## Tool Versions
CONTROLLER_TOOLS_VERSION ?= v0.20.1
PROTOC_GEN_GO_VERSION ?= v1.36.11
PROTOC_GEN_GO_GRPC_VERSION ?= v1.6.1
HELM_VALUES_SCHEMA_JSON_VERSION ?= v2.3.1

#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= $(shell v='$(call gomodver,sigs.k8s.io/controller-runtime)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_VERSION manually (controller-runtime replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?([0-9]+)\.([0-9]+).*/release-\1.\2/')

#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= $(shell v='$(call gomodver,k8s.io/api)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_K8S_VERSION manually (k8s.io/api replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?[0-9]+\.([0-9]+).*/1.\1/')

GOLANGCI_LINT_VERSION ?= v2.13.2
.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@"$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path || { \
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

.PHONY: helm-values-schema-json
helm-values-schema-json: $(HELM_VALUES_SCHEMA_JSON) ## Download helm-values-schema-json locally if necessary.
$(HELM_VALUES_SCHEMA_JSON): $(LOCALBIN)
	$(call go-install-tool,$(HELM_VALUES_SCHEMA_JSON),github.com/losisin/helm-values-schema-json/v2,$(HELM_VALUES_SCHEMA_JSON_VERSION))

.PHONY: generate-chart-values
generate-chart-values: $(HELM_VALUES_SCHEMA_JSON)
	$(HELM_VALUES_SCHEMA_JSON) --no-additional-properties \
		--values charts/network-enforcer/values.yaml \
		--output charts/network-enforcer/values.schema.json

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))
	@test -f .custom-gcl.yml && { \
		echo "Building custom golangci-lint with plugins..." && \
		$(GOLANGCI_LINT) custom --destination $(LOCALBIN) --name golangci-lint-custom && \
		mv -f $(LOCALBIN)/golangci-lint-custom $(GOLANGCI_LINT); \
	} || true

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] && [ "$$(readlink -- "$(1)" 2>/dev/null)" = "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f "$(1)" ;\
GOBIN="$(LOCALBIN)" go install $${package} ;\
mv "$(LOCALBIN)/$$(basename "$(1)")" "$(1)-$(3)" ;\
} ;\
ln -sf "$$(realpath "$(1)-$(3)")" "$(1)"
endef

define gomodver
$(shell go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' $(1) 2>/dev/null)
endef

GOLDMANE_VERSION ?= v3.32.1
GOLDMANE_PROTO_DIR = internal/scraper/goldmane
.PHONY: download-calico-goldmane-proto
download-calico-goldmane-proto: ## Download Calico Goldmane proto file.
	@echo "Downloading Goldmane proto file..."
	mkdir -p $(GOLDMANE_PROTO_DIR)
	curl -fsSL https://raw.githubusercontent.com/projectcalico/calico/$(GOLDMANE_VERSION)/goldmane/proto/api.proto -o $(GOLDMANE_PROTO_DIR)/api.proto

.PHONY: generate-calico-goldmane-proto
generate-calico-goldmane-proto: download-calico-goldmane-proto protoc-gen-go protoc-gen-go-grpc ## Generate Go code from Goldmane proto definitions.
	@echo "Generating Go code from Goldmane proto definitions..."
	PATH=$(LOCALBIN):$(PATH) protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(GOLDMANE_PROTO_DIR)/api.proto

# The e2e suite installs the selected data-plane provider (default: istio) and
# the network-enforcer chart on a dedicated kind cluster.
#
# Use `E2E_PROVIDER` env variable to select the provider (`istio`, `cilium`, or `calico`).
# Example: `make test-e2e E2E_PROVIDER=istio`
#
# Set E2E_USE_EXISTING_CLUSTER=true to reuse an existing cluster.
# Set E2E_DEPENDENCIES=none to skip the provider/cert-manager installation (useful with existing clusters).
# Example: `make test-e2e E2E_USE_EXISTING_CLUSTER=true E2E_DEPENDENCIES=none`
# Set E2E_NO_REBUILD=true to skip image building.  This is useful when you're developing new e2e tests.
.PHONY: test-e2e
test-e2e:
ifneq ($(E2E_USE_EXISTING_CLUSTER),true)
ifeq ($(E2E_NO_REBUILD),)
	$(MAKE) build-controller-image
endif
endif
	@echo "🧪 Running e2e tests with '$(E2E_PROVIDER)' provider..."
	E2E_PROVIDER=$(E2E_PROVIDER) E2E_USE_EXISTING_CLUSTER=$(E2E_USE_EXISTING_CLUSTER) E2E_DEPENDENCIES=$(E2E_DEPENDENCIES) go test -v ./test/e2e/... -count=1

# Create kind cluster and install selected provider with dependencies.
# Example: `make setup-dev-cluster E2E_PROVIDER=istio`
.PHONY: setup-dev-cluster
setup-dev-cluster:
	@echo "🛠️ Setting up dev cluster with '$(E2E_PROVIDER)' provider..."
	make test-e2e E2E_INSTALL_CLUSTER_ONLY=kind
	@echo "🛠️ Calling tilt with '$(E2E_PROVIDER)' provider..."
	tilt up -- --provider=$(E2E_PROVIDER)

.PHONY: delete-dev-cluster
delete-dev-cluster:
	@echo "🛠️ Delete dev cluster..."
	kind delete cluster

.PHONY: helm-unit-test
helm-unit-test:
	helm unittest charts/network-enforcer/ --file "tests/**/*_test.yaml"
