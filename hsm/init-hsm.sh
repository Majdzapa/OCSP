#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# hsm/init-hsm.sh
# SoftHSM2 Dedicated Container:
#   1. Sets up SoftHSM2 directories and configuration
#   2. Initializes the PKCS#11 token if it does not exist yet
#   3. Runs as a persistent, healthy HSM service for relying applications
#
# Deliberately NOT done here: no CA generation, no key pair, no certificate.
# Signing keys are generated inside the token on demand by the OCSP responder
# (Signing Certificates > Generate CSR). The CSR is signed by a CA you create in
# the KMS, and the issued certificate is imported and activated by the user.
# =============================================================================

HSM_TOKEN_LABEL="${HSM_TOKEN_LABEL:-ocsp-signing}"
HSM_PIN="${HSM_PIN:-1234}"
HSM_SO_PIN="${HSM_SO_PIN:-12345678}"
SOFTHSM2_CONF="${SOFTHSM2_CONF:-/etc/softhsm2/softhsm2.conf}"

echo "=== [HSM Service] Initializing SoftHSM2 Container ==="
echo "[*] Token Label:    ${HSM_TOKEN_LABEL}"

mkdir -p /etc/softhsm2 /var/lib/softhsm/tokens
if [ ! -f "${SOFTHSM2_CONF}" ]; then
    cat <<EOF > "${SOFTHSM2_CONF}"
directories.tokendir = /var/lib/softhsm/tokens
objectstore.backend = file
log.level = INFO
EOF
fi

export SOFTHSM2_CONF

# Initialize token if not present
if softhsm2-util --show-slots | grep -q "Label:.*${HSM_TOKEN_LABEL}"; then
    echo "[✓] SoftHSM2 token '${HSM_TOKEN_LABEL}' already exists."
else
    echo "[*] Initializing SoftHSM2 token '${HSM_TOKEN_LABEL}'..."
    softhsm2-util --init-token --free --label "${HSM_TOKEN_LABEL}" --so-pin "${HSM_SO_PIN}" --pin "${HSM_PIN}"
fi

# Ensure tokens directory is accessible
chmod -R 777 /var/lib/softhsm/tokens /etc/softhsm2 2>/dev/null || true

echo "=== [HSM Service] SoftHSM2 token ready. No keys or certificates are pre-provisioned. ==="

# Keep daemon running and healthy
exec tail -f /dev/null
