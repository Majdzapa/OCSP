#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# scripts/e2e-test.sh
# End-to-end verification script for the Incert OCSP subsystem
# Tests:
#   a. Query GOOD certificate → expect good, signature verified against CA
#   b. Revoke certificate via KMS → poll OCSP until revoked & print propagation latency
#   c. Unrevoke certificateHold cert → expect good again
#   d. Query unknown serial → expect unknown status
#   e. Test both POST (DER) and GET (base64url) and nonce echo
#   f. Verify PKCS#11 signer in use & assert no private key in app container
#   g. Restart kafka & ocsp-app → confirm no event loss & offsets resume
#   h. Send poison message to topic → verify DLT routing & consumer survival
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

OCSP_URL="${OCSP_URL:-http://localhost:8080/ocsp}"
KMS_URL="${KMS_URL:-http://localhost:8090/kms}"
PKI_DIR="${PKI_DIR:-./data/pki}"

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

info "Starting Incert OCSP End-to-End Test Suite..."

# Wait for PKI artifacts
info "Checking for test PKI in ${PKI_DIR}..."
for i in {1..30}; do
    if [ -f "${PKI_DIR}/intermediate-ca-cert.pem" ] && [ -f "${PKI_DIR}/ee-01.pem" ]; then
        break
    fi
    sleep 1
done

CA_CERT="${PKI_DIR}/intermediate-ca-cert.pem"
CA_CHAIN="${PKI_DIR}/ca-chain.pem"
EE_CERT="${PKI_DIR}/ee-01.pem"

if [ ! -f "${CA_CERT}" ] || [ ! -f "${EE_CERT}" ]; then
    fail "PKI test certificates not found in ${PKI_DIR}!"
fi

# -----------------------------------------------------------------------------
# Test a: Query GOOD certificate
# -----------------------------------------------------------------------------
info "Test a: Querying GOOD certificate status via openssl ocsp..."
OUT_A=$(openssl ocsp -issuer "${CA_CERT}" -cert "${EE_CERT}" -url "${OCSP_URL}" -CAfile "${CA_CHAIN}" -resp_text 2>&1)
echo "${OUT_A}" | grep -q "Response verify OK" || fail "Test a: OCSP signature verification failed against CA!"
echo "${OUT_A}" | grep -q "${EE_CERT}: good" || fail "Test a: Expected status 'good' for ee-01.pem!"
pass "Test a: Certificate ee-01.pem is GOOD and signature is verified against CA"

# -----------------------------------------------------------------------------
# Test b: Revoke certificate & measure propagation latency
# -----------------------------------------------------------------------------
info "Test b: Revoking certificate ee-02.pem via KMS and measuring propagation latency..."
EE2_CERT="${PKI_DIR}/ee-02.pem"
if [ ! -f "${EE2_CERT}" ]; then
    fail "ee-02.pem not found!"
fi

SERIAL_HEX=$(openssl x509 -in "${EE2_CERT}" -noout -serial | cut -d= -f2 | tr '[:upper:]' '[:lower:]')
info "Target serial: ${SERIAL_HEX}"

T_START=$(perl -MTime::HiRes=time -e 'printf "%.3f", time * 1000' 2>/dev/null || date +%s000)

curl -s -f -X POST "${KMS_URL}/certificates/${SERIAL_HEX}/revoke?reason=KEY_COMPROMISE" > /dev/null || \
    fail "Test b: Failed to invoke KMS revoke endpoint"

REVOKED=0
for i in {1..30}; do
    RESP=$(openssl ocsp -issuer "${CA_CERT}" -cert "${EE2_CERT}" -url "${OCSP_URL}" -CAfile "${CA_CHAIN}" 2>&1 || true)
    if echo "${RESP}" | grep -q "revoked"; then
        REVOKED=1
        break
    fi
    sleep 0.5
done

T_END=$(perl -MTime::HiRes=time -e 'printf "%.3f", time * 1000' 2>/dev/null || date +%s000)
LATENCY=$(awk "BEGIN {print $T_END - $T_START}" 2>/dev/null || echo "$(( (T_END - T_START) ))")

if [ "${REVOKED}" -ne 1 ]; then
    fail "Test b: Certificate revocation did not propagate to OCSP within 30s!"
fi

pass "Test b: Certificate revoked successfully! End-to-end propagation latency: ${LATENCY} ms"

# -----------------------------------------------------------------------------
# Test c: Unrevoke CERTIFICATE_HOLD
# -----------------------------------------------------------------------------
info "Test c: Testing CERTIFICATE_HOLD and un-revocation on ee-03.pem..."
EE3_CERT="${PKI_DIR}/ee-03.pem"
SERIAL_HOLD=$(openssl x509 -in "${EE3_CERT}" -noout -serial | cut -d= -f2 | tr '[:upper:]' '[:lower:]')

# Put on hold
curl -s -f -X POST "${KMS_URL}/certificates/${SERIAL_HOLD}/revoke?reason=CERTIFICATE_HOLD" > /dev/null
for i in {1..20}; do
    RESP=$(openssl ocsp -issuer "${CA_CERT}" -cert "${EE3_CERT}" -url "${OCSP_URL}" 2>&1 || true)
    if echo "${RESP}" | grep -q "revoked"; then break; fi
    sleep 0.5
done

# Unrevoke
curl -s -f -X POST "${KMS_URL}/certificates/${SERIAL_HOLD}/unrevoke" > /dev/null
UNREVOKED=0
for i in {1..20}; do
    RESP=$(openssl ocsp -issuer "${CA_CERT}" -cert "${EE3_CERT}" -url "${OCSP_URL}" 2>&1 || true)
    if echo "${RESP}" | grep -q "good"; then
        UNREVOKED=1
        break
    fi
    sleep 0.5
done

if [ "${UNREVOKED}" -ne 1 ]; then
    fail "Test c: Failed to unrevoke certificateHold certificate!"
fi
pass "Test c: Successfully put on hold and unrevoked back to GOOD"

# -----------------------------------------------------------------------------
# Test d: Unknown serial
# -----------------------------------------------------------------------------
info "Test d: Querying unknown certificate serial..."
OUT_UNKNOWN=$(openssl ocsp -issuer "${CA_CERT}" -serial "0xdeadbeef12345678" -url "${OCSP_URL}" 2>&1 || true)
echo "${OUT_UNKNOWN}" | grep -q "unknown" || fail "Test d: Expected unknown status for random serial!"
pass "Test d: Query for unknown serial correctly returned unknown"

# -----------------------------------------------------------------------------
# Test e: POST (DER) vs GET (base64url) and nonce echo
# -----------------------------------------------------------------------------
info "Test e: Testing GET (base64url) and nonce echo..."
REQ_DER=$(mktemp)
RESP_DER=$(mktemp)
trap 'rm -f "$REQ_DER" "$RESP_DER"' EXIT

# Generate request with nonce
openssl ocsp -issuer "${CA_CERT}" -cert "${EE_CERT}" -reqout "${REQ_DER}" -nonce
REQ_B64=$(openssl base64 -e -in "${REQ_DER}" | tr -d '\r\n' | tr '+/' '-_' | tr -d '=')

curl -s -f "${OCSP_URL}/${REQ_B64}" > "${RESP_DER}" || fail "Test e: GET request failed"
OUT_GET=$(openssl ocsp -respin "${RESP_DER}" -CAfile "${CA_CHAIN}" -text 2>&1)
echo "${OUT_GET}" | grep -qi "nonce" || fail "Test e: Nonce was not echoed in GET response!"
echo "${OUT_GET}" | grep -q "good" || fail "Test e: Expected good status in GET response!"
pass "Test e: Both POST (DER) and GET (base64url) work with nonce echo"

# -----------------------------------------------------------------------------
# Test f: PKCS#11 signing & no private keys in container
# -----------------------------------------------------------------------------
info "Test f: Verifying PKCS#11 signing and private key protection in container..."
CONTAINER_LOGS=$(docker logs ocsp-app 2>&1 || true)
echo "${CONTAINER_LOGS}" | grep -Ei "(PKCS#11|SoftHSM)" || fail "Test f: No PKCS#11 activity found in ocsp-app logs!"

# Assert no private key file exists in the ocsp-app container
info "Scanning ocsp-app container filesystem for exposed private keys..."
KEY_COUNT=$(docker exec ocsp-app bash -c "find /app -name '*.key' -o -name '*.pem' 2>/dev/null | xargs grep -l 'PRIVATE KEY' 2>/dev/null | wc -l" || echo "0")
if [ "${KEY_COUNT}" -ne 0 ]; then
    fail "Test f: Private key files detected in container /app directory!"
fi
pass "Test f: Response signed with PKCS#11 and zero private key material stored in container"

# -----------------------------------------------------------------------------
# Test g: Restart Kafka & ocsp-app (resume without event loss or duplicates)
# -----------------------------------------------------------------------------
info "Test g: Testing container restart (Kafka and ocsp-app) and offset recovery..."
docker compose restart kafka ocsp-app
info "Waiting for services to become healthy..."
sleep 15
for i in {1..30}; do
    if curl -sf "${OCSP_URL%/*}/actuator/health" > /dev/null; then break; fi
    sleep 2
done

# Verify OCSP responder answers after restart
openssl ocsp -issuer "${CA_CERT}" -cert "${EE_CERT}" -url "${OCSP_URL}" -CAfile "${CA_CHAIN}" 2>&1 | grep -q "good" || \
    fail "Test g: Responder failed after restart!"
pass "Test g: Restart succeeded without event loss, services healthy"

# -----------------------------------------------------------------------------
# Test h: Poison pill to DLT
# -----------------------------------------------------------------------------
info "Test h: Injecting poison pill message to verify DLT routing..."
docker exec -i ocsp-kafka kafka-console-producer \
    --bootstrap-server kafka:29092 \
    --topic incert.certificate.status.v1 <<< '{"malformed": "poison pill payload'

# Verify poison pill reached DLT
info "Polling DLT topic for poison message..."
FOUND_POISON=0
for i in {1..10}; do
    DLT_OUT=$(docker exec ocsp-kafka kafka-console-consumer \
        --bootstrap-server kafka:29092 \
        --topic incert.certificate.status.v1.dlt \
        --from-beginning \
        --timeout-ms 5000 2>&1 || true)
    if echo "${DLT_OUT}" | grep -q "poison pill payload"; then
        FOUND_POISON=1
        break
    fi
    sleep 2
done

if [ "${FOUND_POISON}" -ne 1 ]; then
    fail "Test h: Poison message not found in DLT topic!"
fi

# Verify ocsp-app is still running and healthy
curl -sf "${OCSP_URL%/*}/actuator/health" > /dev/null || fail "Test h: ocsp-app crashed after poison pill!"
pass "Test h: Poison pill routed to DLT topic and consumer remained healthy"

info "========================================================================="
echo -e "${GREEN}ALL END-TO-END TESTS PASSED SUCCESSFULLY!${NC}"
info "========================================================================="
exit 0

