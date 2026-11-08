#!/usr/bin/env bash
set -euo pipefail

# Run SoftHSM initialization if script exists
if [ -f "/scripts/init-softhsm.sh" ]; then
    bash /scripts/init-softhsm.sh || echo "[!] SoftHSM init exited with warning, continuing..."
fi

# Execute main command
exec "$@"

