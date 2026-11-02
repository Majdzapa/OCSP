#!/usr/bin/env bash
# dev-stop.sh — Stop all OCSP dev services started by dev-start.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOGS="$ROOT/.dev-logs"

GREEN='\033[0;32m'; NC='\033[0m'

for svc in kms-mock ocsp-auth ocsp-sync ocsp-responder ocsp-admin-api ocsp-console; do
    PID_FILE="$LOGS/${svc}.pid"
    if [[ -f "$PID_FILE" ]]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID"
            echo -e "${GREEN}[STOP]${NC} $svc (PID $PID)"
        fi
        rm -f "$PID_FILE"
    fi
done

echo "Infrastructure (MariaDB/RabbitMQ) left running."
echo "To stop: docker compose down"
