.PHONY: help image-source build build-web build-image build-runtime-image build-web-image docker-up docker-down docker-logs fmt fmt-rust lint lint-rust lint-web lint-helm test test-rust test-web test-go test-python test-python-deps test-java test-helm e2e-python e2e-prepare e2e e2e-k8s e2e-docker e2e-cleanup package-chart release release-push release-verify clean

CARGO ?= cargo
GO ?= go
PYTHON ?= python3
MAVEN ?= mvn
MAVEN_FLAGS ?= -B
NPM ?= npm
GOPROXY ?= https://goproxy.cn,direct
CONTAINER_CLI ?= docker
CONTAINER_BUILD_FLAGS ?=
VERSION ?= $(shell sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)
VERSION := $(if $(VERSION),$(VERSION),0.1.0)
GHCR_IMAGE ?= ghcr.io/wl4g/authguard
GHCR_WEB_IMAGE ?= ghcr.io/wl4g/authguard-web
AUTHGUARD_CARGO_FEATURES ?= web3
VITE_AUTHN_BASE_URL ?=
VITE_AUTHZ_BASE_URL ?=
VITE_REOWN_PROJECT_ID ?=
HELM_OCI_REGISTRY ?= oci://ghcr.io/wl4g/charts
RELEASE_DIR ?= dist
USE_CASE_DIR := use-cases/customer-growth-job-service
E2E_DIR := $(USE_CASE_DIR)
E2E_VENV_DIR ?= $(E2E_DIR)/util/.venv
E2E_PYTHON := $(E2E_VENV_DIR)/bin/python
PYTHON_TEST_VENV_DIR ?= target/python-test-venv
PYTHON_TEST := $(PYTHON_TEST_VENV_DIR)/bin/python
E2E_K8S_SCENARIOS ?= 01,02,00,20,10,26,30,31,40,41,42
E2E_K8S_ARGS ?=
E2E_DOCKER_SCENARIOS ?= $(E2E_K8S_SCENARIOS)
E2E_DOCKER_ARGS ?=
E2E_DEPLOYER ?= kubernetes
WEB_DIR := web
DOCKER_COMPOSE_FILE := deploy/docker/docker-compose.yaml
DOCKER_ENV_FILE := deploy/docker/.env

# Accept the same region flags as the portable E2E image matrix.
ifeq ($(origin IN_CN_GFW),undefined)
ifneq ($(filter IN_GFW IN_CN_GFW,$(E2E_IMAGE_NETWORK)),)
IN_CN_GFW := true
else ifeq ($(E2E_IMAGE_NETWORK),NON_GFW)
IN_CN_GFW := false
else ifneq ($(origin IN_GFW),undefined)
ifeq ($(filter $(IN_GFW),true false 1 0 IN_GFW NON_GFW),)
$(error IN_GFW must be true or false)
endif
IN_CN_GFW := $(if $(filter true 1 IN_GFW,$(IN_GFW)),true,false)
else ifneq ($(origin NON_GFW),undefined)
ifeq ($(filter $(NON_GFW),true false 1 0 IN_GFW NON_GFW),)
$(error NON_GFW must be true or false)
endif
IN_CN_GFW := $(if $(filter true 1 NON_GFW,$(NON_GFW)),false,true)
endif
endif

IMAGE_SOURCE_GOALS := image-source build-image build-runtime-image \
	build-web-image e2e e2e-k8s e2e-docker release
ifneq ($(strip $(filter $(IMAGE_SOURCE_GOALS),$(MAKECMDGOALS))),)
ifeq ($(origin IN_CN_GFW),undefined)
IN_CN_GFW := $(shell \
	if command -v curl >/dev/null 2>&1; then \
		status=$$(curl -sS --noproxy '*' -o /dev/null -w '%{http_code}' \
			--connect-timeout 3 --max-time 5 https://registry-1.docker.io/v2/ \
			2>/dev/null || true); \
		if [ "$$status" = 200 ] || [ "$$status" = 401 ]; then \
			echo false; \
		else \
			echo true; \
		fi; \
	else \
		echo true; \
	fi)
endif
else ifeq ($(origin IN_CN_GFW),undefined)
# Formatting, unit tests, Helm rendering, and help do not consume container
# images. Avoid adding a registry network probe to those unrelated targets.
IN_CN_GFW := false
endif
ifeq ($(filter $(IN_CN_GFW),true false),)
$(error IN_CN_GFW must be true or false)
endif

TEST_PROXY_PRESENT := $(strip $(HTTPS_PROXY)$(https_proxy)$(HTTP_PROXY)$(http_proxy))
BUILD_PROXY := $(or $(HTTPS_PROXY),$(https_proxy),$(HTTP_PROXY),$(http_proxy))
ifneq ($(TEST_PROXY_PRESENT),)
CONTAINER_BUILD_FLAGS += --network=host --build-arg HTTPS_PROXY=$(BUILD_PROXY) --build-arg HTTP_PROXY=$(BUILD_PROXY)
endif

AUTHGUARD_IMAGE_SOURCE ?= $(if $(filter true,$(IN_CN_GFW)),aliyun,global)
ifeq ($(filter $(AUTHGUARD_IMAGE_SOURCE),aliyun global),)
$(error AUTHGUARD_IMAGE_SOURCE must be aliyun or global)
endif
AUTHGUARD_E2E_IMAGE_SOURCE ?= $(AUTHGUARD_IMAGE_SOURCE)
ifeq ($(filter $(AUTHGUARD_E2E_IMAGE_SOURCE),aliyun global),)
$(error AUTHGUARD_E2E_IMAGE_SOURCE must be aliyun or global)
endif
export AUTHGUARD_E2E_IMAGE_SOURCE

ifeq ($(AUTHGUARD_IMAGE_SOURCE),aliyun)
WEB_NODE_IMAGE ?= registry.cn-shenzhen.aliyuncs.com/wl4g/node:22-alpine
WEB_RUNTIME_IMAGE ?= registry.cn-shenzhen.aliyuncs.com/wl4g/nginxinc_nginx-unprivileged:1.27-alpine
RUST_BUILDER_IMAGE ?= registry.cn-shenzhen.aliyuncs.com/wl4g/rust:1.99.1-slim
else
WEB_NODE_IMAGE ?= docker.io/library/node:22-alpine
WEB_RUNTIME_IMAGE ?= docker.io/nginxinc/nginx-unprivileged:1.27-alpine
RUST_BUILDER_IMAGE ?= docker.io/library/rust:1.99.1-slim
endif

ifeq ($(TEST_PROXY_PRESENT),)
GO_NETWORK_ENV := GOPROXY=$(GOPROXY)
else
GO_NETWORK_ENV :=
endif

.DEFAULT_GOAL := help

help:
	@echo "Authguard -- Makefile"
	@echo ""
	@echo "  Build:"
	@echo "    make build         Build backend, AuthGuard Web, Golang, Python, Java, TS modules."
	@echo "    make build-web     Build the AuthGuard React Dashboard and Hosted Login UI."
	@echo "    make build-image   Build the AuthGuard server release image."
	@echo "    make docker-up     Start the local Docker Compose AuthGuard topology."
	@echo "    make docker-down   Stop the local Docker Compose topology."
	@echo "    make docker-logs   Follow local Docker Compose logs."
	@echo ""
	@echo "  Quality:"
	@echo "    make fmt           Check Rust formatting."
	@echo "    make lint          Run Rust clippy with warnings denied."
	@echo "    make lint-helm     Lint and render the Authguard Helm chart."
	@echo ""
	@echo "  Test:"
	@echo "    make test          Run product lint, tests, and Helm checks."
	@echo "    make test-rust     Run Rust workspace tests."
	@echo "    make test-go       Run Go adapter tests."
	@echo "    make test-python   Run Python adapter tests."
	@echo "    make test-java     Run Java adapter tests."
	@echo "    make test-helm     Verify vendored dependencies, lint, and render Helm manifests."
	@echo "    make e2e           Run the complete Kubernetes E2E scenarios."
	@echo "    make e2e-k8s       Clean-deploy and run the complete AuthN/AuthZ/UI/observability matrix."
	@echo "    make e2e-docker    Run the same complete matrix through Docker Compose."
	@echo "    make e2e-cleanup   Remove resources owned by E2E_DEPLOYER=kubernetes|docker."
	@echo "    make release       Build, package, publish, and pull-verify image/chart artifacts."
	@echo ""
	@echo "  Utils:"
	@echo "    make image-source  Show the auto-detected container image source."
	@echo "    make clean         Remove local build artifacts."

image-source:
	@echo "IN_CN_GFW=$(IN_CN_GFW)"
	@echo "AUTHGUARD_IMAGE_SOURCE=$(AUTHGUARD_IMAGE_SOURCE)"
	@echo "AUTHGUARD_E2E_IMAGE_SOURCE=$(AUTHGUARD_E2E_IMAGE_SOURCE)"
	@echo "WEB_NODE_IMAGE=$(WEB_NODE_IMAGE)"
	@echo "RUST_BUILDER_IMAGE=$(RUST_BUILDER_IMAGE)"

build: build-web
	$(CARGO) build --workspace
	$(MAVEN) $(MAVEN_FLAGS) -f src/sdk/java/pom.xml -DskipTests install

build-web:
	cd $(WEB_DIR) && $(NPM) ci && $(NPM) run build

build-image: build-runtime-image

build-runtime-image:
	@size_kb=$$(du -sk target 2>/dev/null | cut -f1); \
	  if [ "$${size_kb:-0}" -gt 10485760 ]; then \
	    echo "target/ exceeds 10 GiB; cleaning before the Rust image build"; \
	    $(CARGO) clean; \
	  fi
	$(CONTAINER_CLI) build $(CONTAINER_BUILD_FLAGS) -f deploy/docker/Dockerfile \
		--build-arg RUST_BUILDER_IMAGE="$(RUST_BUILDER_IMAGE)" \
		--build-arg AUTHGUARD_CARGO_FEATURES="$(AUTHGUARD_CARGO_FEATURES)" \
		-t $(GHCR_IMAGE):$(VERSION) -t $(GHCR_IMAGE):latest .

build-web-image:
	$(CONTAINER_CLI) build $(CONTAINER_BUILD_FLAGS) -f $(WEB_DIR)/Dockerfile \
		--build-arg NODE_IMAGE="$(WEB_NODE_IMAGE)" \
		--build-arg WEB_IMAGE="$(WEB_RUNTIME_IMAGE)" \
		--build-arg VITE_AUTHN_BASE_URL="$(VITE_AUTHN_BASE_URL)" \
		--build-arg VITE_AUTHZ_BASE_URL="$(VITE_AUTHZ_BASE_URL)" \
		--build-arg VITE_REOWN_PROJECT_ID="$(VITE_REOWN_PROJECT_ID)" \
		-t $(GHCR_WEB_IMAGE):$(VERSION) -t $(GHCR_WEB_IMAGE):latest $(WEB_DIR)

docker-up:
	@test -f $(DOCKER_ENV_FILE) || (echo "copy deploy/docker/.env.example to $(DOCKER_ENV_FILE) and replace its placeholders" >&2; exit 1)
	$(CONTAINER_CLI) compose --env-file $(DOCKER_ENV_FILE) -f $(DOCKER_COMPOSE_FILE) up -d

docker-down:
	$(CONTAINER_CLI) compose --env-file $(DOCKER_ENV_FILE) -f $(DOCKER_COMPOSE_FILE) down

docker-logs:
	$(CONTAINER_CLI) compose --env-file $(DOCKER_ENV_FILE) -f $(DOCKER_COMPOSE_FILE) logs -f

fmt: fmt-rust

fmt-rust:
	$(CARGO) fmt --all --check

lint: lint-rust lint-web

lint-rust:
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

lint-web:
	cd $(WEB_DIR) && $(NPM) ci && $(NPM) run typecheck

lint-helm: test-helm

test: fmt lint test-rust test-web test-go test-python test-java test-helm

test-rust:
	$(CARGO) test --workspace --all-features

test-web:
	cd $(WEB_DIR) && $(NPM) run build

test-go:
	cd src/sdk/golang && $(GO_NETWORK_ENV) $(GO) test ./...

test-python: test-python-deps
	PYTHONPATH="$(CURDIR)/src/sdk/python" $(PYTHON_TEST) -m unittest discover -s "$(CURDIR)/src/sdk/python/tests" -v

test-python-deps:
	@test -x $(PYTHON_TEST) || $(PYTHON) -m venv $(PYTHON_TEST_VENV_DIR)
	$(PYTHON_TEST) -m pip install --disable-pip-version-check -r src/sdk/python/requirements.txt

test-java:
	$(MAVEN) $(MAVEN_FLAGS) -f src/sdk/java/pom.xml install

test-helm:
	test -f deploy/helm/authguard/charts/gateway-helm-v1.9.0.tgz
	test -f deploy/helm/authguard/charts/redis-cluster-8.8.2.tgz
	test -f deploy/helm/authguard/charts/postgresql-18.8.13.tgz
	helm dependency list deploy/helm/authguard
	helm lint deploy/helm/authguard
	helm template authguard deploy/helm/authguard >/dev/null

e2e-python:
	test -x $(E2E_PYTHON) || $(PYTHON) -m venv $(E2E_VENV_DIR)
	$(E2E_PYTHON) -m pip install --disable-pip-version-check -r $(E2E_DIR)/requirements.txt

e2e-prepare: e2e-python
	cd $(WEB_DIR) && $(NPM) ci
	$(E2E_PYTHON) -m playwright install --only-shell chromium

e2e: e2e-prepare
	$(E2E_PYTHON) $(E2E_DIR)/runner.py

e2e-k8s: e2e-prepare
	$(E2E_PYTHON) $(E2E_DIR)/runner.py --deployer kubernetes --scenario $(E2E_K8S_SCENARIOS) --timeout 1800 $(E2E_K8S_ARGS)

e2e-docker: e2e-prepare
	$(E2E_PYTHON) $(E2E_DIR)/runner.py --deployer docker --scenario $(E2E_DOCKER_SCENARIOS) --timeout 1800 $(E2E_DOCKER_ARGS)

e2e-cleanup: e2e-python
	$(E2E_PYTHON) $(E2E_DIR)/runner.py --deployer $(E2E_DEPLOYER) --cleanup --timeout 1800

package-chart: test-helm
	mkdir -p $(RELEASE_DIR)
	helm package deploy/helm/authguard --destination $(RELEASE_DIR) \
		--version $(VERSION) --app-version $(VERSION)

release: build-runtime-image build-web-image package-chart release-push release-verify

release-push:
	$(CONTAINER_CLI) push $(GHCR_IMAGE):$(VERSION)
	$(CONTAINER_CLI) push $(GHCR_IMAGE):latest
	$(CONTAINER_CLI) push $(GHCR_WEB_IMAGE):$(VERSION)
	$(CONTAINER_CLI) push $(GHCR_WEB_IMAGE):latest
	helm push $(RELEASE_DIR)/authguard-$(VERSION).tgz $(HELM_OCI_REGISTRY)

release-verify:
	$(CONTAINER_CLI) pull $(GHCR_IMAGE):$(VERSION) >/dev/null
	$(CONTAINER_CLI) image inspect $(GHCR_IMAGE):$(VERSION) >/dev/null
	$(CONTAINER_CLI) pull $(GHCR_WEB_IMAGE):$(VERSION) >/dev/null
	$(CONTAINER_CLI) image inspect $(GHCR_WEB_IMAGE):$(VERSION) >/dev/null
	@pull_dir=$$(mktemp -d); \
	  trap 'rm -rf "$$pull_dir"' EXIT; \
	  helm pull $(HELM_OCI_REGISTRY)/authguard --version $(VERSION) --destination "$$pull_dir"; \
	  test -s "$$pull_dir/authguard-$(VERSION).tgz"; \
	  helm show chart "$$pull_dir/authguard-$(VERSION).tgz" >/dev/null; \
	  echo "verified OCI Helm chart: $(HELM_OCI_REGISTRY)/authguard:$(VERSION)"

clean:
	find . -type d \( -name target -o -name __pycache__ -o -name .pytest_cache -o -name .mypy_cache -o -name .ruff_cache \) -prune -exec sh -c 'find "$$1" -depth -delete' sh {} \;
	find $(WEB_DIR) -type d \( -name node_modules -o -name dist \) -prune -exec sh -c 'find "$$1" -depth -delete' sh {} \;
