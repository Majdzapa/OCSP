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
HSM_SECONDARY_TOKEN_LABEL="${HSM_SECONDARY_TOKEN_LABEL:-ocsp-signing-2}"
HSM_PIN="${HSM_PIN:-1234}"
HSM_SO_PIN="${HSM_SO_PIN:-12345678}"
HSM_SECONDARY_PIN="${HSM_SECONDARY_PIN:-${HSM_PIN}}"
HSM_SECONDARY_SO_PIN="${HSM_SECONDARY_SO_PIN:-${HSM_SO_PIN}}"
SOFTHSM2_CONF="${SOFTHSM2_CONF:-/etc/softhsm2/softhsm2.conf}"

echo "=== [HSM Service] Initializing SoftHSM2 Container ==="
echo "[*] Primary Token Label:   ${HSM_TOKEN_LABEL}"
echo "[*] Secondary Token Label: ${HSM_SECONDARY_TOKEN_LABEL}"

mkdir -p /etc/softhsm2 /var/lib/softhsm/tokens
if [ ! -f "${SOFTHSM2_CONF}" ]; then
    cat <<EOF > "${SOFTHSM2_CONF}"
directories.tokendir = /var/lib/softhsm/tokens
objectstore.backend = file
log.level = INFO
EOF
fi

export SOFTHSM2_CONF

init_token_if_missing() {
    local label="$1"
    local so_pin="$2"
    local pin="$3"
    if [ -z "${label}" ]; then
        return 0
    fi
    if softhsm2-util --show-slots | grep -q "Label:.*${label}"; then
        echo "[✓] SoftHSM2 token '${label}' already exists."
    else
        echo "[*] Initializing SoftHSM2 token '${label}'..."
        softhsm2-util --init-token --free --label "${label}" --so-pin "${so_pin}" --pin "${pin}"
    fi
}

init_token_if_missing "${HSM_TOKEN_LABEL}" "${HSM_SO_PIN}" "${HSM_PIN}"
init_token_if_missing "${HSM_SECONDARY_TOKEN_LABEL}" "${HSM_SECONDARY_SO_PIN}" "${HSM_SECONDARY_PIN}"

# Ensure tokens directory is accessible
chmod -R 777 /var/lib/softhsm/tokens /etc/softhsm2 2>/dev/null || true

echo "=== [HSM Service] SoftHSM2 tokens ready. No keys or certificates are pre-provisioned. ==="

# Keep daemon running and healthy
exec tail -f /dev/null
