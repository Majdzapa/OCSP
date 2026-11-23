#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# scripts/build-all.sh
# Builds all standalone Spring Boot applications independently
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== [1/6] Building PKCS11J Wrapper + Native JNI ==="
(cd "${ROOT_DIR}/pkcs11j" && mvn clean install -DskipTests)

echo "=== [2/6] Building HSM Signer Protobuf/gRPC Contract ==="
(cd "${ROOT_DIR}/hsm-signer-proto" && mvn clean install -DskipTests)

echo "=== [3/6] Building HSM Signer gRPC Service ==="
(cd "${ROOT_DIR}/hsm-signer" && mvn clean package -DskipTests)

echo "=== [4/6] Building KMS Simulator ==="
(cd "${ROOT_DIR}/kms-simulator" && mvn clean package -DskipTests)

echo "=== [5/6] Building OCSP Responder ==="
(cd "${ROOT_DIR}/ocsp-responder" && mvn clean package -DskipTests)

echo "=== [6/6] Building OCSP Client & OCSP Console ==="
(cd "${ROOT_DIR}/ocsp-client" && mvn clean package -DskipTests)
(cd "${ROOT_DIR}/ocsp-console" && yarn build)

echo "=== All standalone services built successfully! ==="
