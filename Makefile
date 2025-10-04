# FILE: Makefile
# One-command developer/release workflow for TCD
# Targets: lint test bench serve verify helm sbom release
# CI can simply run: `make ci`
SHELL := /bin/bash

# -------- Project & toolchain --------
PYTHON ?= python3
PIP    ?= $(PYTHON) -m pip
DOCKER ?= docker
HELM   ?= helm

PKG := tcd

# Resolve version from pyproject.toml or git describe (fallback)
VERSION_PY  := $(shell sed -n 's/^version[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' pyproject.toml | head -n1)
VERSION_GIT := $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
VERSION     := $(if $(VERSION_PY),$(VERSION_PY),$(VERwaSION_GIT))

# Container image coordinates
IMAGE_REPO ?= ghcr.io/your-org/tcd
IMAGE      ?= $(IMAGE_REPO):$(VERSION)

# Helm chart
HELM_CHART_DIR ?= deploy/helm/tcd
HELM_RELEASE   ?= tcd
HELM_NAMESPACE ?= default

# Sample receipts (for `make verify`). If not present, the target prints tool version.
RECEIPTS_JSONL ?= examples/receipts.jsonl

# -------- Utility --------
.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z0-9_.-]+:.*?##/ { printf "\033[36m%-22s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# -------- Dev setup --------
.PHONY: init
init: ## Install dev dependencies (editable) and pre-commit hooks
	$(PIP) install --upgrade pip wheel
	$(PIP) install -e .[test,otel,grpc]
	$(PIP) install pre-commit build
	pre-commit install

# -------- Quality --------
.PHONY: format
format: ## Auto-fix with ruff + ruff-format
	@command -v ruff >/dev/null 2>&1 || $(PIP) install ruff
	ruff --fix .
	ruff format .

.PHONY: lint
lint: ## Run linters (pre-commit) and ruff check
	@command -v pre-commit >/dev/null 2>&1 || $(PIP) install pre-commit
	pre-commit run --all-files || true
	@command -v ruff >/dev/null 2>&1 || $(PIP) install ruff
	ruff check .

# -------- Tests & Bench --------
.PHONY: test
test: ## Run unit tests (pytest)
	$(PYTHON) -m pytest -q

.PHONY: bench
bench: ## Run micro-benchmarks (pytest-benchmark)
	$(PYTHON) -m pytest -q --benchmark-only --benchmark-min-time=0.1 --benchmark-min-rounds=5

# -------- Local run --------
.PHONY: serve
serve: ## Run HTTP service locally (FastAPI / uvicorn)
	@echo "TCD version: $(VERSION)"
	TCD_PROM_HTTP=1 TCD_CONFIG_VERSION=$(VERSION) tcd-serve-http --host 0.0.0.0 --port 8080

.PHONY: verify
verify: ## Verify receipts JSONL if present; otherwise print verifier version
	@if [ -f "$(RECEIPTS_JSONL)" ]; then \
	  echo "[*] Verifying JSONL chain: $(RECEIPTS_JSONL)"; \
	  tcd-verify chain --jsonl --heads "$(RECEIPTS_JSONL)"; \
	else \
	  echo "[*] No receipts JSONL found at $(RECEIPTS_JSONL). Printing tool version:"; \
	  tcd-verify version; \
	fi

# -------- Build artifacts --------
DIST_DIR := dist

.PHONY: wheel
wheel: ## Build wheel + sdist into dist/
	@command -v build >/dev/null 2>&1 || $(PIP) install build
	rm -rf $(DIST_DIR)
	$(PYTHON) -m build --outdir $(DIST_DIR)
	@ls -lh $(DIST_DIR) || true

.PHONY: docker-build
docker-build: ## Build container image ($(IMAGE))
	$(DOCKER) build --pull -t $(IMAGE) .
	@echo "[*] Built image: $(IMAGE)"

.PHONY: docker-digest
docker-digest: ## Print repo digest for image (after build/push)
	@$(DOCKER) pull $(IMAGE) >/dev/null || true
	@echo -n "[*] RepoDigest: "; \
	$(DOCKER) inspect --format='{{index .RepoDigests 0}}' $(IMAGE) || true

.PHONY: sbom
sbom: ## Generate SBOM + cosign attest; writes out.env for TCD_IMAGE_DIGEST
	@chmod +x scripts/sbom.sh
	./scripts/sbom.sh "$(IMAGE)" out cyclonedx-json
	@echo "[*] SBOM + attestation done."

# -------- Helm (k8s) --------
.PHONY: helm
helm: ## Helm lint + template chart
	$(HELM) lint $(HELM_CHART_DIR)
	$(HELM) template $(HELM_RELEASE) $(HELM_CHART_DIR) --namespace $(HELM_NAMESPACE) \
	  --set image.repository=$(IMAGE_REPO) --set image.tag=$(VERSION) > /tmp/tcd-rendered.yaml
	@echo "[*] Rendered manifest: /tmp/tcd-rendered.yaml"

.PHONY: helm-install
helm-install: ## helm upgrade --install the chart
	$(HELM) upgrade --install $(HELM_RELEASE) $(HELM_CHART_DIR) \
	  --namespace $(HELM_NAMESPACE) --create-namespace \
	  --set image.repository=$(IMAGE_REPO) --set image.tag=$(VERSION)

.PHONY: helm-uninstall
helm-uninstall: ## helm uninstall the release
	$(HELM) uninstall $(HELM_RELEASE) --namespace $(HELM_NAMESPACE) || true

# -------- Release pipeline --------
CHANGELOG := CHANGELOG-$(VERSION).md

.PHONY: changelog
changelog: ## Generate a simple changelog from last tag
	@{ \
	  LAST=$$(git describe --tags --abbrev=0 2>/dev/null || echo ""); \
	  echo "# TCD $(VERSION) — $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')"; \
	  echo; \
	  if [ -n "$$LAST" ]; then \
	    echo "Changes since $$LAST:"; \
	    git log --no-merges --pretty='- %h %s (%an)' "$$LAST"..HEAD; \
	  else \
	    echo "Initial release or no tags found."; \
	    git log --no-merges --pretty='- %h %s (%an)'; \
	  fi; \
	} > $(CHANGELOG)
	@echo "[*] Wrote $(CHANGELOG)"

.PHONY: release
release: clean format lint test wheel docker-build sbom changelog ## Full release: code → wheel → image → SBOM → changelog
	@echo "[*] Release artifacts ready:"
	@ls -lh $(DIST_DIR) || true
	@$(MAKE) docker-digest

.PHONY: ci
ci: format lint test wheel docker-build sbom ## CI entrypoint

# -------- Housekeeping --------
.PHONY: clean
clean: ## Remove build/test artifacts
	rm -rf $(DIST_DIR) build .pytest_cache .mypy_cache .ruff_cache \
	   **/__pycache__ **/*.pyc **/*.pyo out.env sbom*.json* attestation*.json || true

.PHONY: version
version: ## Print resolved version and image
	@echo "VERSION=$(VERSION)"
	@echo "IMAGE=$(IMAGE)"
