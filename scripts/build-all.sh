#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# scripts/build-all.sh
# Builds all standalone Spring Boot applications & console independently
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== [1/2] Building OCSP Responder ==="
(cd "${ROOT_DIR}/ocsp-responder" && mvn clean package -DskipTests)

echo "=== [2/2] Building OCSP Console ==="
(cd "${ROOT_DIR}/ocsp-console" && yarn build)

echo "=== All services built successfully! ==="
