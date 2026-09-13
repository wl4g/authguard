.PHONY: help build build-image fmt fmt-rust lint lint-rust lint-helm test test-rust test-go test-python test-java test-helm e2e e2e-k3s package-chart release release-push release-verify clean

CARGO ?= cargo
GO ?= go
PYTHON ?= python3
MAVEN ?= mvn
MAVEN_FLAGS ?= -q
GOPROXY ?= https://goproxy.cn,direct
CONTAINER_CLI ?= docker
CONTAINER_BUILD_FLAGS ?=
VERSION ?= $(shell sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)
VERSION := $(if $(VERSION),$(VERSION),0.1.0)
GHCR_IMAGE ?= ghcr.io/wl4g/authguard
ALIYUN_IMAGE ?= registry.cn-shenzhen.aliyuncs.com/wl4g/authguard
HELM_OCI_REGISTRY ?= oci://ghcr.io/wl4g/charts
RELEASE_DIR ?= dist
USE_CASE_DIR := use-cases/customer-growth-job-service
E2E_DEPLOY_DIR := $(USE_CASE_DIR)/e2e/deploy

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
	@echo "    make build         Build Rust workspace and Java reactor without tests."
	@echo "    make build-image   Build the single Authguard runtime image."
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
	@echo "    make e2e           Clean-build the portable 53-scenario authorization suite."
	@echo "    make e2e-k3s       Redeploy Keycloak/Envoy/Authguard/Jaeger/data services on k3s."
	@echo "    make release       Build, package, publish, and pull-verify image/chart artifacts."
	@echo ""
	@echo "  Utils:"
	@echo "    make clean         Remove local build artifacts."

build:
	$(CARGO) build --workspace
	$(MAVEN) $(MAVEN_FLAGS) -f src/adapters/java/pom.xml -DskipTests install
	$(MAVEN) $(MAVEN_FLAGS) -f $(E2E_DEPLOY_DIR)/springboot-jdbc-service/pom.xml -DskipTests package
	$(MAVEN) $(MAVEN_FLAGS) -f $(E2E_DEPLOY_DIR)/springboot-jpa-service/pom.xml -DskipTests package

build-image:
	@size_kb=$$(du -sk target 2>/dev/null | cut -f1); \
	  if [ "$${size_kb:-0}" -gt 10485760 ]; then \
	    echo "target/ exceeds 10 GiB; cleaning before the Rust image build"; \
	    $(CARGO) clean; \
	  fi
	$(CONTAINER_CLI) build $(CONTAINER_BUILD_FLAGS) -f deploy/docker/Dockerfile \
		-t $(GHCR_IMAGE):$(VERSION) -t $(GHCR_IMAGE):latest \
		-t $(ALIYUN_IMAGE):$(VERSION) -t $(ALIYUN_IMAGE):latest .

fmt: fmt-rust

fmt-rust:
	$(CARGO) fmt --all --check

lint: lint-rust

lint-rust:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

lint-helm: test-helm

test: fmt lint test-rust test-go test-python test-java test-helm

test-rust:
	$(CARGO) test --workspace

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
	helm dependency list deploy/helm/authguard
	helm lint deploy/helm/authguard
	helm template authguard deploy/helm/authguard >/dev/null

e2e:
	$(PYTHON) $(USE_CASE_DIR)/e2e/runner.py

e2e-k3s:
	$(PYTHON) $(USE_CASE_DIR)/e2e/runner.py --scenario 00 --timeout 1800

package-chart: test-helm
	mkdir -p $(RELEASE_DIR)
	helm package deploy/helm/authguard --destination $(RELEASE_DIR) \
		--version $(VERSION) --app-version $(VERSION)

release: build-image package-chart release-push release-verify

release-push:
	$(CONTAINER_CLI) push $(GHCR_IMAGE):$(VERSION)
	$(CONTAINER_CLI) push $(GHCR_IMAGE):latest
	$(CONTAINER_CLI) push $(ALIYUN_IMAGE):$(VERSION)
	$(CONTAINER_CLI) push $(ALIYUN_IMAGE):latest
	helm push $(RELEASE_DIR)/authguard-$(VERSION).tgz $(HELM_OCI_REGISTRY)

release-verify:
	@pull_dir=$$(mktemp -d); \
	  trap 'rm -rf "$$pull_dir"' EXIT; \
	  helm pull $(HELM_OCI_REGISTRY)/authguard --version $(VERSION) --destination "$$pull_dir"; \
	  test -s "$$pull_dir/authguard-$(VERSION).tgz"; \
	  helm show chart "$$pull_dir/authguard-$(VERSION).tgz" >/dev/null; \
	  echo "verified OCI Helm chart: $(HELM_OCI_REGISTRY)/authguard:$(VERSION)"

clean:
	find . -type d \( -name target -o -name __pycache__ -o -name .pytest_cache -o -name .mypy_cache -o -name .ruff_cache \) -prune -exec sh -c 'find "$$1" -depth -delete' sh {} \;
