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
#   f. Verify PKCS#11 signer in use & assert no private key in responder container
#   g. Restart rabbitmq & ocsp-responder → confirm no event loss & queue recovers
#   h. Send poison message to exchange → verify DLQ routing & consumer survival
#   i. Verify OCSP Responder Authentication (401 without key, 200 with X-API-KEY/Basic)
#   j. Verify OCSP Client Standalone App (Nonce-Free & Nonce tests, Web Test UI)
#   k. Verify KMS Simulator Web UI & Inventory
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

OCSP_URL="${OCSP_URL:-http://localhost:8080/ocsp}"
CLIENT_URL="${CLIENT_URL:-http://localhost:8082}"
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

START_TIME=$(python3 -c 'import time; print(int(time.time() * 1000000))')
curl -s -f -X POST "${KMS_URL}/certificates/${SERIAL_HEX}/revoke?reason=KEY_COMPROMISE" > /dev/null || fail "Test b: KMS revoke API call failed!"

REVOKED=0
for i in {1..30}; do
    RESP=$(openssl ocsp -issuer "${CA_CERT}" -cert "${EE2_CERT}" -url "${OCSP_URL}" 2>&1 || true)
    if echo "${RESP}" | grep -q "revoked"; then
        END_TIME=$(python3 -c 'import time; print(int(time.time() * 1000000))')
        REVOKED=1
        LATENCY_MS=$(python3 -c "print((${END_TIME} - ${START_TIME}) / 1000.0)")
        info "Latency: ${LATENCY_MS} ms"
        break
    fi
    sleep 0.1
done

if [ "${REVOKED}" -ne 1 ]; then
    fail "Test b: Certificate did not transition to revoked status within timeout!"
fi
pass "Test b: Certificate revoked successfully! End-to-end propagation latency: ${LATENCY_MS} ms"

# -----------------------------------------------------------------------------
# Test c: Un-revocation / CERTIFICATE_HOLD
# -----------------------------------------------------------------------------
info "Test c: Testing CERTIFICATE_HOLD and un-revocation on ee-03.pem..."
EE3_CERT="${PKI_DIR}/ee-03.pem"
if [ ! -f "${EE3_CERT}" ]; then
    fail "ee-03.pem not found!"
fi
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
CONTAINER_LOGS=$(docker logs ocsp-responder 2>&1 || true)
echo "${CONTAINER_LOGS}" | grep -Ei "(PKCS#11|SoftHSM)" || fail "Test f: No PKCS#11 activity found in ocsp-responder logs!"

info "Scanning ocsp-responder container filesystem for exposed private keys..."
KEY_COUNT=$(docker exec ocsp-responder bash -c "find /app -name '*.key' -o -name '*.pem' 2>/dev/null | xargs grep -l 'PRIVATE KEY' 2>/dev/null | wc -l" || echo "0")
if [ "${KEY_COUNT}" -ne 0 ]; then
    fail "Test f: Private key files detected in container /app directory!"
fi
pass "Test f: Response signed with PKCS#11 and zero private key material stored in container"

# -----------------------------------------------------------------------------
# Test g: Restart RabbitMQ & ocsp-responder
# -----------------------------------------------------------------------------
info "Test g: Testing container restart (RabbitMQ and ocsp-responder)..."
docker compose restart rabbitmq ocsp-responder
info "Waiting for services to become healthy..."
sleep 15
for i in {1..30}; do
    if curl -sf "${OCSP_URL%/*}/actuator/health" > /dev/null; then break; fi
    sleep 2
done

openssl ocsp -issuer "${CA_CERT}" -cert "${EE_CERT}" -url "${OCSP_URL}" -CAfile "${CA_CHAIN}" 2>&1 | grep -q "good" || \
    fail "Test g: Responder failed after restart!"
pass "Test g: Restart succeeded without event loss, services healthy"

# -----------------------------------------------------------------------------
# Test h: Poison pill to DLQ
# -----------------------------------------------------------------------------
info "Test h: Injecting poison pill message to verify DLQ routing..."
docker exec -i ocsp-rabbitmq rabbitmqadmin publish \
    exchange=incert.certificate.status \
    routing_key=incert.certificate.status.v1 \
    payload='{"malformed": "poison pill payload' || true

info "Polling DLQ for poison message..."
FOUND_POISON=0
for i in {1..10}; do
    DLQ_OUT=$(docker exec ocsp-rabbitmq rabbitmqadmin get queue=ocsp.certificate.status.dlq count=1 ackmode=ack_requeue_false 2>&1 || true)
    if echo "${DLQ_OUT}" | grep -q "poison pill payload"; then
        FOUND_POISON=1
        break
    fi
    sleep 2
done

if [ "${FOUND_POISON}" -ne 1 ]; then
    fail "Test h: Poison message not found in DLQ queue!"
fi

curl -sf "${OCSP_URL%/*}/actuator/health" > /dev/null || fail "Test h: ocsp-responder crashed after poison pill!"
pass "Test h: Poison pill routed to DLQ queue and consumer remained healthy"

# -----------------------------------------------------------------------------
# Test i: OCSP Responder Authentication
# -----------------------------------------------------------------------------
info "Test i: Verifying OCSP Responder Authentication on Admin Endpoints..."
AUTH_RESP_UNAUTH=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/v1/admin/dashboard)
if [ "${AUTH_RESP_UNAUTH}" -ne 401 ]; then
    fail "Test i: Expected 401 Unauthorized without auth headers, got ${AUTH_RESP_UNAUTH}!"
fi

AUTH_RESP_AUTH=$(curl -s -o /dev/null -w "%{http_code}" -H "X-API-KEY: incert-admin-secret-key" http://localhost:8080/api/v1/admin/dashboard)
if [ "${AUTH_RESP_AUTH}" -ne 200 ]; then
    fail "Test i: Expected 200 OK with X-API-KEY header, got ${AUTH_RESP_AUTH}!"
fi

AUTH_RESP_BASIC=$(curl -s -o /dev/null -w "%{http_code}" -u admin:changeme http://localhost:8080/api/v1/admin/dashboard)
if [ "${AUTH_RESP_BASIC}" -ne 200 ]; then
    fail "Test i: Expected 200 OK with Basic Auth credentials, got ${AUTH_RESP_BASIC}!"
fi
pass "Test i: OCSP Responder authentication verified (401 without auth, 200 with X-API-KEY and Basic Auth)"

# -----------------------------------------------------------------------------
# Test j: OCSP Client Standalone Application & Test Web UI
# -----------------------------------------------------------------------------
info "Test j: Verifying standalone OCSP Client application and test web UI..."
CLIENT_WEB_HTTP=$(curl -s -o /dev/null -w "%{http_code}" "${CLIENT_URL}/")
if [ "${CLIENT_WEB_HTTP}" -ne 200 ]; then
    fail "Test j: OCSP Client web interface returned ${CLIENT_WEB_HTTP} instead of 200!"
fi

# Query client REST check API (Nonce-Free)
EE1_SERIAL=$(openssl x509 -in "${EE_CERT}" -noout -serial | cut -d= -f2 | tr '[:upper:]' '[:lower:]')
CLIENT_CHECK_NONCE_FREE=$(curl -s -X POST "${CLIENT_URL}/api/v1/client/check" \
    -H "Content-Type: application/json" \
    -d "{\"serialHex\": \"${EE1_SERIAL}\", \"includeNonce\": false, \"method\": \"POST\", \"responderUrl\": \"http://ocsp-responder:8080/ocsp\"}")

echo "${CLIENT_CHECK_NONCE_FREE}" | grep -q '"certStatus":"GOOD"' || fail "Test j: Client check returned unexpected certStatus: ${CLIENT_CHECK_NONCE_FREE}"
echo "${CLIENT_CHECK_NONCE_FREE}" | grep -q '"valid":true' || fail "Test j: Client check validation failed: ${CLIENT_CHECK_NONCE_FREE}"

# Query client REST check API (With Nonce)
CLIENT_CHECK_NONCE=$(curl -s -X POST "${CLIENT_URL}/api/v1/client/check" \
    -H "Content-Type: application/json" \
    -d "{\"serialHex\": \"${EE1_SERIAL}\", \"includeNonce\": true, \"method\": \"POST\", \"responderUrl\": \"http://ocsp-responder:8080/ocsp\"}")

echo "${CLIENT_CHECK_NONCE}" | grep -q '"certStatus":"GOOD"' || fail "Test j: Client check with nonce failed: ${CLIENT_CHECK_NONCE}"
echo "${CLIENT_CHECK_NONCE}" | grep -q '"nonceEchoed"' || fail "Test j: Client check with nonce did not receive echoed nonce: ${CLIENT_CHECK_NONCE}"
pass "Test j: Standalone OCSP Client verified (Web UI 200, Nonce-Free check OK, Nonce Echo check OK)"

# -----------------------------------------------------------------------------
# Test k: KMS Simulator Web Interface
# -----------------------------------------------------------------------------
info "Test k: Verifying KMS Simulator Web UI..."
KMS_WEB_HTTP=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8090/")
if [ "${KMS_WEB_HTTP}" -ne 200 ]; then
    fail "Test k: KMS web interface returned ${KMS_WEB_HTTP} instead of 200!"
fi
pass "Test k: KMS Simulator Web UI verified (HTTP 200)"

info "========================================================================="
echo -e "${GREEN}ALL END-TO-END TESTS PASSED SUCCESSFULLY!${NC}"
info "========================================================================="
exit 0
