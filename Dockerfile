# FILE: Dockerfile
# Multi-stage build: compile once, run on distroless (nonroot).
# Goal: small, reproducible, production-ready image with verifiable supply chain.

# ---------- Builder ----------
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Build tooling only in builder layer
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential gcc git ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Project files
WORKDIR /src
COPY pyproject.toml README.md ./
COPY tcd ./tcd
COPY .pre-commit-config.yaml ./.pre-commit-config.yaml

# Create venv and install package (base deps only; otel/grpc are optional extras)
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip wheel && \
    /opt/venv/bin/pip install --no-cache-dir . && \
    /opt/venv/bin/python -m compileall -q -j 4 /opt/venv

# ---------- Runtime ----------
# Distroless: smallest, no shell, nonroot by default
FROM gcr.io/distroless/python3-debian12:nonroot

# Copy virtualenv
COPY --from=builder /opt/venv /opt/venv

# Runtime env
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Service defaults (overridable at runtime)
    TCD_PORT=8080 \
    TCD_PROMETHEUS_PORT=8000 \
    TCD_PROM_HTTP=1 \
    TCD_CONFIG_VERSION=1

WORKDIR /srv/app

# Expose service (HTTP) and metrics (Prometheus)
EXPOSE 8080 8000

# Healthcheck without shell — use venv python
HEALTHCHECK --interval=10s --timeout=2s --start-period=10s --retries=3 \
  CMD ["/opt/venv/bin/python","-c","import os,urllib.request,sys;port=os.getenv('TCD_PORT','8080');url=f'http://127.0.0.1:{port}/healthz';urllib.request.urlopen(url,timeout=1).read();sys.exit(0)"]

# Run as venv entrypoint (console_script)
ENTRYPOINT ["/opt/venv/bin/tcd-serve-http"]
# Example overrides:
#   docker run -e TCD_IMAGE_DIGEST=<repo-digest> -p 8080:8080 -p 8000:8000 your/tcd:0.10.2
#   docker run --read-only --tmpfs /tmp:rw,nosuid,nodev,size=32m ...
# FILE: .dockerignore
# Keep context minimal to reduce build time/size and improve reproducibility.

# VCS / CI
.git
.github
.gitignore

# tests / benches / examples not needed at runtime
tests
bench
examples
ops
deploy
charts
docs
*.ipynb

# Python caches
__pycache__/
*.pyc
*.pyo
*.pyd
*.pydist
*.egg-info
dist
build
.eggs
.tox
.pytest_cache
.mypy_cache

# Virtualenvs
.venv
venv
env

# Local tooling
.idea
.vscode

# Node/Front-end leftovers if any
node_modules

# OS
.DS_Store
Thumbs.db

# SBOM outputs (generated)
sbom*.json
attestation*.json
# FILE: scripts/sbom.sh
#!/usr/bin/env bash
# Generate SBOM (syft) and sign/attest image (cosign).
# Usage:
#   scripts/sbom.sh ghcr.io/your-org/tcd:0.10.2 [OUTPUT_PREFIX] [FORMAT]
# Example:
#   scripts/sbom.sh ghcr.io/your-org/tcd:0.10.2 out cyclonedx-json
# Requires: syft, cosign, docker (logged in if private registry).
set -euo pipefail

IMAGE="${1:-}"
OUT="${2:-out}"
SYFT_FORMAT="${3:-cyclonedx-json}"  # cyclonedx-json | spdx-json

if [[ -z "${IMAGE}" ]]; then
  echo "Usage: $0 <image[:tag|@digest]> [output_prefix] [cyclonedx-json|spdx-json]" >&2
  exit 2
fi

command -v syft >/dev/null 2>&1 || { echo "syft not found (install from https://github.com/anchore/syft)"; exit 2; }
command -v cosign >/dev/null 2>&1 || { echo "cosign not found (install from https://github.com/sigstore/cosign)"; exit 2; }
command -v docker >/dev/null 2>&1 || { echo "docker CLI not found"; exit 2; }

# Pull to materialize repo digest (for reproducible receipts).
echo "[*] Pulling image ${IMAGE}..."
docker pull "${IMAGE}" >/dev/null

# Resolve digests
REPO_DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "${IMAGE}" || true)"
IMAGE_ID="$(docker inspect --format='{{.Id}}' "${IMAGE}" || true)"

echo "[*] Image repo digest: ${REPO_DIGEST:-<none>}"
echo "[*] Local image ID:    ${IMAGE_ID:-<none>}"

# Generate SBOM
SBOM_FILE="${OUT}.sbom.${SYFT_FORMAT}.json"
echo "[*] Generating SBOM (${SYFT_FORMAT}) -> ${SBOM_FILE}"
syft "${IMAGE}" -o "${SYFT_FORMAT}" > "${SBOM_FILE}"

# Choose cosign predicate type based on format and cosign version
COSIGN_TYPE="cyclonedx"
if [[ "${SYFT_FORMAT}" == "spdx-json" || "${SYFT_FORMAT}" == "spdx" ]]; then
  # Detect supported keyword (spdxjson vs spdx) for this cosign version
  if cosign attest --help 2>/dev/null | grep -qi "spdxjson"; then
    COSIGN_TYPE="spdxjson"
  else
    COSIGN_TYPE="spdx"
  fi
fi

# Sign the image (keyless OIDC by default; set COSIGN_EXPERIMENTAL=1 if needed)
echo "[*] Signing image with cosign (keyless if configured)..."
COSIGN_YES=${COSIGN_YES:-false}
if [[ "${COSIGN_YES}" == "true" ]]; then
  cosign sign --yes "${IMAGE}"
else
  cosign sign "${IMAGE}"
fi

# Create attestation with SBOM as predicate
echo "[*] Attesting SBOM with cosign (type=${COSIGN_TYPE})..."
if [[ "${COSIGN_YES}" == "true" ]]; then
  cosign attest --yes --predicate "${SBOM_FILE}" --type "${COSIGN_TYPE}" "${IMAGE}"
else
  cosign attest --predicate "${SBOM_FILE}" --type "${COSIGN_TYPE}" "${IMAGE}"
fi

# Write helper env file for runtime to inject digest (optional)
if [[ -n "${REPO_DIGEST}" ]]; then
  DIGEST_ONLY="${REPO_DIGEST##*@}"
  echo "TCD_IMAGE_DIGEST=${DIGEST_ONLY}" > "${OUT}.env"
  echo "[*] Wrote ${OUT}.env (export this when running: docker run --env-file ${OUT}.env ...)"
fi

echo "[*] Done."
echo "    SBOM:      ${SBOM_FILE}"
echo "    RepoDigest:${REPO_DIGEST:-<none>}  (use -e TCD_IMAGE_DIGEST=\${digest} to pin receipts)"
