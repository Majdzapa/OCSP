#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# scripts/build-all.sh
# Builds all standalone Spring Boot applications independently
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== [1/3] Building KMS Simulator ==="
(cd "${ROOT_DIR}/kms-simulator" && mvn clean package -DskipTests)

echo "=== [2/3] Building OCSP Responder ==="
(cd "${ROOT_DIR}/ocsp-responder" && mvn clean package -DskipTests)

echo "=== [3/3] Building OCSP Client & Testing Service ==="
(cd "${ROOT_DIR}/ocsp-client" && mvn clean package -DskipTests)

echo "=== All standalone services built successfully! ==="
