#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# scripts/init-softhsm.sh
# Idempotently initialises SoftHSM2 for the Incert OCSP responder:
#   1. Initialises token (softhsm2-util --init-token) if not already present
#   2. Generates RSA 3072 key pair inside the token (non-extractable)
#   3. Issues a delegated OCSP signing certificate signed by the Incert CA
#   4. Imports the certificate into the token with matching label/ID
# =============================================================================

HSM_TOKEN_LABEL="${HSM_TOKEN_LABEL:-ocsp-signing}"
HSM_PIN="${HSM_PIN:-1234}"
HSM_SO_PIN="${HSM_SO_PIN:-12345678}"
HSM_KEY_LABEL="${HSM_KEY_LABEL:-ocsp-signing-key}"
HSM_PKCS11_LIBRARY="${HSM_PKCS11_LIBRARY:-/usr/lib/softhsm/libsofthsm2.so}"
PKI_DIR="${PKI_DIR:-/data/pki}"

echo "=== Initializing SoftHSM2 (Token: ${HSM_TOKEN_LABEL}, Key: ${HSM_KEY_LABEL}) ==="

# Ensure SoftHSM2 config and tokens directory exist
SOFTHSM2_CONF="${SOFTHSM2_CONF:-/etc/softhsm2/softhsm2.conf}"
if [ ! -f "${SOFTHSM2_CONF}" ]; then
    mkdir -p /etc/softhsm2 /var/lib/softhsm/tokens
    cat <<EOF > "${SOFTHSM2_CONF}"
directories.tokendir = /var/lib/softhsm/tokens
objectstore.backend = file
log.level = INFO
EOF
fi

export SOFTHSM2_CONF

# 1. Initialize token if not already initialized
if softhsm2-util --show-slots | grep -q "Label:.*${HSM_TOKEN_LABEL}"; then
    echo "[✓] SoftHSM2 token '${HSM_TOKEN_LABEL}' already exists."
else
    echo "[*] Initializing SoftHSM2 token '${HSM_TOKEN_LABEL}'..."
    softhsm2-util --init-token --free --label "${HSM_TOKEN_LABEL}" --so-pin "${HSM_SO_PIN}" --pin "${HSM_PIN}"
fi

# 2. Check if key already exists
if pkcs11-tool --module "${HSM_PKCS11_LIBRARY}" --token-label "${HSM_TOKEN_LABEL}" --login --pin "${HSM_PIN}" --list-objects 2>/dev/null | grep -q "${HSM_KEY_LABEL}"; then
    echo "[✓] Key '${HSM_KEY_LABEL}' already exists in token."
    exit 0
fi

echo "[*] Generating RSA 3072 keypair inside token '${HSM_TOKEN_LABEL}'..."
pkcs11-tool --module "${HSM_PKCS11_LIBRARY}" \
    --token-label "${HSM_TOKEN_LABEL}" \
    --login --pin "${HSM_PIN}" \
    --keypairgen \
    --key-type rsa:3072 \
    --label "${HSM_KEY_LABEL}" \
    --id 01

# 3. Wait for CA material if needed
echo "[*] Checking for CA files in ${PKI_DIR}..."
MAX_WAIT=30
WAITED=0
while [ ! -f "${PKI_DIR}/intermediate-ca-cert.pem" ] || [ ! -f "${PKI_DIR}/intermediate-ca-key.pem.TESTONLY" ]; do
    if [ "${WAITED}" -ge "${MAX_WAIT}" ]; then
        echo "[!] Warning: CA files not found in ${PKI_DIR} after ${MAX_WAIT}s. Skipping delegated cert generation."
        exit 0
    fi
    echo "[*] Waiting for KMS to seed PKI artifacts... (${WAITED}s/${MAX_WAIT}s)"
    sleep 2
    WAITED=$((WAITED + 2))
done

# Read public key from token
PUBKEY_DER=$(mktemp)
PUBKEY_PEM=$(mktemp)
EXT_FILE=$(mktemp)
CERT_PEM=$(mktemp)
CERT_DER=$(mktemp)

trap 'rm -f "$PUBKEY_DER" "$PUBKEY_PEM" "$EXT_FILE" "$CERT_PEM" "$CERT_DER"' EXIT

echo "[*] Extracting public key from token..."
pkcs11-tool --module "${HSM_PKCS11_LIBRARY}" \
    --token-label "${HSM_TOKEN_LABEL}" \
    --login --pin "${HSM_PIN}" \
    --read-object \
    --type pubkey \
    --label "${HSM_KEY_LABEL}" > "${PUBKEY_DER}"

openssl rsa -inform DER -outform PEM -pubin -in "${PUBKEY_DER}" -out "${PUBKEY_PEM}" 2>/dev/null || \
openssl pkey -inform DER -outform PEM -pubin -in "${PUBKEY_DER}" -out "${PUBKEY_PEM}"

cat <<'EOF' > "${EXT_FILE}"
[v3_ocsp]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
extendedKeyUsage = critical, OCSPSigning
1.3.6.1.5.5.7.48.1.5 = ASN1:NULL
EOF

echo "[*] Issuing delegated OCSP signing certificate..."
# Issue delegated OCSP cert directly using intermediate CA key and pubkey
openssl x509 -req \
    -days 30 \
    -in <(openssl req -new -key "${PKI_DIR}/intermediate-ca-key.pem.TESTONLY" -subj "/CN=Incert Delegated OCSP Signer,O=Incert,C=CH" -days 30) \
    -CA "${PKI_DIR}/intermediate-ca-cert.pem" \
    -CAkey "${PKI_DIR}/intermediate-ca-key.pem.TESTONLY" \
    -CAcreateserial \
    -extfile "${EXT_FILE}" \
    -extensions v3_ocsp \
    -force_pubkey "${PUBKEY_PEM}" \
    -out "${CERT_PEM}"

openssl x509 -in "${CERT_PEM}" -outform DER -out "${CERT_DER}"

echo "[*] Importing certificate into token..."
pkcs11-tool --module "${HSM_PKCS11_LIBRARY}" \
    --token-label "${HSM_TOKEN_LABEL}" \
    --login --pin "${HSM_PIN}" \
    --write-object "${CERT_DER}" \
    --type cert \
    --label "${HSM_KEY_LABEL}" \
    --id 01

echo "[✓] SoftHSM2 initialisation complete."

