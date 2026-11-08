#!/usr/bin/env bash
set -euo pipefail

echo "=== Stopping Incert OCSP Subsystem ==="
docker compose down -v --remove-orphans
