.PHONY: help build build-web build-image build-runtime-image build-web-image docker-up docker-down docker-logs fmt fmt-rust lint lint-rust lint-web lint-helm test test-rust test-web test-go test-python test-java test-helm e2e-python e2e-prepare e2e e2e-k3s e2e-cleanup package-chart release release-push release-verify clean

CARGO ?= cargo
GO ?= go
PYTHON ?= python3
MAVEN ?= mvn
MAVEN_FLAGS ?= -q
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
E2E_DEPLOY_DIR := $(USE_CASE_DIR)/e2e/deploy
E2E_DIR := $(USE_CASE_DIR)/e2e
E2E_VENV_DIR ?= $(E2E_DIR)/.venv
E2E_PYTHON := $(E2E_VENV_DIR)/bin/python
E2E_K3S_SCENARIOS ?= 00,01,02,03,20,10,21,22,23,24,25,26,30,40
WEB_DIR := web
DOCKER_COMPOSE_FILE := deploy/docker/docker-compose.yaml
DOCKER_ENV_FILE := deploy/docker/.env

ifeq ($(IN_CN_GFW),true)
HTTPS_PROXY ?= http://127.0.0.1:8800
HTTP_PROXY ?= $(HTTPS_PROXY)
export HTTPS_PROXY
export HTTP_PROXY
CONTAINER_BUILD_FLAGS += --network=host --build-arg HTTPS_PROXY=$(HTTPS_PROXY) --build-arg HTTP_PROXY=$(HTTP_PROXY)
endif

TEST_PROXY_PRESENT := $(strip $(HTTPS_PROXY)$(https_proxy)$(HTTP_PROXY)$(http_proxy))
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
	@echo "    make build         Build backend, AuthGuard Web, and Java modules."
	@echo "    make build-web     Build the AuthGuard React control-plane UI."
	@echo "    make build-image   Build AuthGuard runtime + AuthGuard Web release images."
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
	@echo "    make test          Run the full local matrix."
	@echo "    make test-rust     Run Rust workspace tests."
	@echo "    make test-go       Run Go adapter and Go use-case tests."
	@echo "    make test-python   Run Python adapter and Python use-case tests."
	@echo "    make test-java     Run Java adapter and Spring Boot use-case tests."
	@echo "    make test-helm     Verify vendored dependencies, lint, and render Helm manifests."
	@echo "    make e2e           Run the portable cross-language verifier groups."
	@echo "    make e2e-k3s       Clean-deploy and run the complete AuthN/AuthZ/UI/observability matrix."
	@echo "    make e2e-cleanup   Remove only the E2E-managed Helm releases and namespace."
	@echo "    make release       Build, package, publish, and pull-verify image/chart artifacts."
	@echo ""
	@echo "  Utils:"
	@echo "    make clean         Remove local build artifacts."

build: build-web
	$(CARGO) build --workspace
	$(MAVEN) $(MAVEN_FLAGS) -f src/adapters/java/pom.xml -DskipTests install
	$(MAVEN) $(MAVEN_FLAGS) -f $(E2E_DEPLOY_DIR)/springboot-jdbc-service/pom.xml -DskipTests package
	$(MAVEN) $(MAVEN_FLAGS) -f $(E2E_DEPLOY_DIR)/springboot-jpa-service/pom.xml -DskipTests package

build-web:
	cd $(WEB_DIR) && $(NPM) ci && $(NPM) run build

build-image: build-runtime-image build-web-image

build-runtime-image:
	@size_kb=$$(du -sk target 2>/dev/null | cut -f1); \
	  if [ "$${size_kb:-0}" -gt 10485760 ]; then \
	    echo "target/ exceeds 10 GiB; cleaning before the Rust image build"; \
	    $(CARGO) clean; \
	  fi
	$(CONTAINER_CLI) build $(CONTAINER_BUILD_FLAGS) -f deploy/docker/Dockerfile \
		--build-arg AUTHGUARD_CARGO_FEATURES="$(AUTHGUARD_CARGO_FEATURES)" \
		-t $(GHCR_IMAGE):$(VERSION) -t $(GHCR_IMAGE):latest .

build-web-image:
	$(CONTAINER_CLI) build $(CONTAINER_BUILD_FLAGS) -f $(WEB_DIR)/Dockerfile \
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
	cd src/adapters/golang && $(GO_NETWORK_ENV) $(GO) test ./...
	cd $(E2E_DEPLOY_DIR)/golang-sqlx-service && $(GO_NETWORK_ENV) $(GO) test ./...

test-python:
	PYTHONPATH="$(CURDIR)/src/adapters/python" $(PYTHON) -m unittest discover -s "$(CURDIR)/src/adapters/python/tests" -v
	PYTHONPATH="$(CURDIR)/src/adapters/python:$(CURDIR)/$(E2E_DEPLOY_DIR)/python-sqlalchemy-service" $(PYTHON) -m unittest discover -s "$(CURDIR)/$(E2E_DEPLOY_DIR)/python-sqlalchemy-service/tests" -v

test-java:
	$(MAVEN) $(MAVEN_FLAGS) -f src/adapters/java/pom.xml install
	$(MAVEN) $(MAVEN_FLAGS) -f $(E2E_DEPLOY_DIR)/springboot-jdbc-service/pom.xml test
	$(MAVEN) $(MAVEN_FLAGS) -f $(E2E_DEPLOY_DIR)/springboot-jpa-service/pom.xml test

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
	$(E2E_PYTHON) -m playwright install chromium

e2e: e2e-prepare
	$(E2E_PYTHON) $(E2E_DIR)/runner.py

e2e-k3s: e2e-prepare
	$(E2E_PYTHON) $(E2E_DIR)/runner.py --scenario $(E2E_K3S_SCENARIOS) --timeout 1800

e2e-cleanup: e2e-python
	$(E2E_PYTHON) $(E2E_DIR)/runner.py --cleanup --timeout 1800

package-chart: test-helm
	mkdir -p $(RELEASE_DIR)
	helm package deploy/helm/authguard --destination $(RELEASE_DIR) \
		--version $(VERSION) --app-version $(VERSION)

release: build-image package-chart release-push release-verify

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
