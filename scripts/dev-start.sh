#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# scripts/dev-start.sh
# Starts the Incert OCSP subsystem via Docker Compose
# =============================================================================

echo "=== Starting Incert OCSP Subsystem ==="
docker compose up --build -d

echo "Waiting for services to become healthy..."
docker compose ps
