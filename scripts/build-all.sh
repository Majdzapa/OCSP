#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# scripts/build-all.sh
# Builds the React frontend (ocsp-console), embeds it into ocsp-responder's
# static resources (along with Antora docs if built), and packages a single
# unified Spring Boot JAR for deployment.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
STATIC_DIR="${ROOT_DIR}/ocsp-responder/src/main/resources/static"

echo "=== [1/2] Building OCSP Console (React SPA) ==="
(cd "${ROOT_DIR}/ocsp-console" && yarn build)

echo "=== Embedding OCSP Console & Docs into ocsp-responder/src/main/resources/static ==="
rm -rf "${STATIC_DIR:?}"/*
mkdir -p "${STATIC_DIR}"
cp -R "${ROOT_DIR}/ocsp-console/dist/." "${STATIC_DIR}/"
if [ -d "${ROOT_DIR}/build/site" ]; then
    mkdir -p "${STATIC_DIR}/docs"
    cp -R "${ROOT_DIR}/build/site/." "${STATIC_DIR}/docs/"
fi

echo "=== [2/2] Packaging Unified OCSP Responder JAR ==="
(cd "${ROOT_DIR}/ocsp-responder" && mvn clean package -DskipTests)

echo "=== Unified OCSP Responder (Backend + OCSP Client + React UI) built successfully! ==="
