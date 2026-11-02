#!/usr/bin/env bash
# =============================================================================
# gen-certs.sh — Generate development keystores and truststores for the OCSP
#               subsystem's KMS mutual TLS integration.
#
# What is generated
# -----------------
#  ca.p12               - Private CA (self-signed root, PKCS12)
#  ca.crt               - CA certificate in DER form (for import)
#  truststore.p12       - PKCS12 containing the CA cert.
#                         All OCSP services import this to TRUST the KMS server.
#  keystore.p12         - PKCS12 containing the OCSP client cert + private key.
#                         OCSP services present this to the KMS for mutual TLS.
#  kms-server.p12       - PKCS12 for the KMS server TLS identity.
#                         (Import into the KMS spring.ssl.bundle or configure
#                          server.ssl.* when enabling TLS on the mock KMS.)
#
# Usage
# -----
#   cd /Users/hedfimajd/OCSP/certs
#   chmod +x gen-certs.sh
#   ./gen-certs.sh
#
# After running, copy / mount the files:
#   truststore.p12  →  $KMS_TRUSTSTORE_PATH  (all OCSP services)
#   keystore.p12    →  $KMS_KEYSTORE_PATH    (all OCSP services)
#   kms-server.p12  →  KMS/src/main/resources/keystore/kms-server.p12
#
# Passwords — change before deploying to any shared environment!
#   CA store password  : changeme
#   truststore password: changeme
#   keystore password  : changeme
#   KMS server password: changeme
# =============================================================================
set -euo pipefail

PASS="changeme"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "🔑 Generating development PKI material in $DIR"

# ---------------------------------------------------------------------------
# 1. Root CA
# ---------------------------------------------------------------------------
echo "  ➜  Generating Root CA..."
keytool -genkeypair \
  -alias ca \
  -keyalg RSA \
  -keysize 4096 \
  -dname "CN=OCSP-Dev-CA, O=Company, C=FR" \
  -validity 3650 \
  -storetype PKCS12 \
  -keystore "$DIR/ca.p12" \
  -storepass "$PASS" \
  -keypass  "$PASS" \
  -ext "BasicConstraints:critical=ca:true,pathlen:1" \
  -ext "KeyUsage:critical=keyCertSign,cRLSign" \
  2>/dev/null
echo "    ✔  ca.p12"

# Export CA certificate (DER)
keytool -exportcert \
  -alias ca \
  -keystore "$DIR/ca.p12" \
  -storepass "$PASS" \
  -file "$DIR/ca.crt" \
  2>/dev/null
echo "    ✔  ca.crt (DER)"

# ---------------------------------------------------------------------------
# 2. Truststore (contains the CA cert — imported by all OCSP services)
# ---------------------------------------------------------------------------
echo "  ➜  Building truststore..."
rm -f "$DIR/truststore.p12"
keytool -importcert \
  -alias ca \
  -file "$DIR/ca.crt" \
  -keystore "$DIR/truststore.p12" \
  -storetype PKCS12 \
  -storepass "$PASS" \
  -noprompt \
  2>/dev/null
echo "    ✔  truststore.p12"

# ---------------------------------------------------------------------------
# 3. OCSP Client Keystore (used by ocsp-responder, ocsp-sync-service to
#    authenticate themselves to the KMS during mTLS handshake)
# ---------------------------------------------------------------------------
echo "  ➜  Generating OCSP client keypair..."
rm -f "$DIR/keystore.p12"
keytool -genkeypair \
  -alias ocsp-client \
  -keyalg RSA \
  -keysize 2048 \
  -dname "CN=ocsp-client, O=Company, C=FR" \
  -validity 365 \
  -storetype PKCS12 \
  -keystore "$DIR/keystore.p12" \
  -storepass "$PASS" \
  -keypass  "$PASS" \
  2>/dev/null

# Create certificate signing request
keytool -certreq \
  -alias ocsp-client \
  -keystore "$DIR/keystore.p12" \
  -storepass "$PASS" \
  -file "$DIR/ocsp-client.csr" \
  2>/dev/null

# CA signs the client CSR
keytool -gencert \
  -alias ca \
  -keystore "$DIR/ca.p12" \
  -storepass "$PASS" \
  -infile  "$DIR/ocsp-client.csr" \
  -outfile "$DIR/ocsp-client.crt" \
  -validity 365 \
  -ext "KeyUsage:critical=digitalSignature" \
  -ext "ExtendedKeyUsage=clientAuth" \
  2>/dev/null

# Import CA cert (chain anchor) then the signed client cert into the keystore
keytool -importcert \
  -alias ca \
  -file "$DIR/ca.crt" \
  -keystore "$DIR/keystore.p12" \
  -storepass "$PASS" \
  -noprompt \
  2>/dev/null
keytool -importcert \
  -alias ocsp-client \
  -file "$DIR/ocsp-client.crt" \
  -keystore "$DIR/keystore.p12" \
  -storepass "$PASS" \
  -noprompt \
  2>/dev/null
echo "    ✔  keystore.p12  (alias: ocsp-client, signed by CA)"

# ---------------------------------------------------------------------------
# 4. KMS Server Keystore (for the KMS mock TLS server identity)
# ---------------------------------------------------------------------------
echo "  ➜  Generating KMS server keypair..."
rm -f "$DIR/kms-server.p12"
keytool -genkeypair \
  -alias kms-server \
  -keyalg RSA \
  -keysize 2048 \
  -dname "CN=localhost, O=Company, C=FR" \
  -validity 365 \
  -storetype PKCS12 \
  -keystore "$DIR/kms-server.p12" \
  -storepass "$PASS" \
  -keypass  "$PASS" \
  2>/dev/null

keytool -certreq \
  -alias kms-server \
  -keystore "$DIR/kms-server.p12" \
  -storepass "$PASS" \
  -file "$DIR/kms-server.csr" \
  2>/dev/null

keytool -gencert \
  -alias ca \
  -keystore "$DIR/ca.p12" \
  -storepass "$PASS" \
  -infile  "$DIR/kms-server.csr" \
  -outfile "$DIR/kms-server.crt" \
  -validity 365 \
  -ext "SAN=dns:localhost,ip:127.0.0.1" \
  -ext "KeyUsage:critical=digitalSignature,keyEncipherment" \
  -ext "ExtendedKeyUsage=serverAuth" \
  2>/dev/null

keytool -importcert -alias ca \
  -file "$DIR/ca.crt" \
  -keystore "$DIR/kms-server.p12" \
  -storepass "$PASS" -noprompt 2>/dev/null
keytool -importcert -alias kms-server \
  -file "$DIR/kms-server.crt" \
  -keystore "$DIR/kms-server.p12" \
  -storepass "$PASS" -noprompt 2>/dev/null
echo "    ✔  kms-server.p12  (CN=localhost, signed by CA)"

# ---------------------------------------------------------------------------
# Clean up intermediate files
# ---------------------------------------------------------------------------
rm -f "$DIR"/*.csr "$DIR"/*.crt

echo ""
echo "✅ All keystores generated in $DIR/"
echo ""
echo "  Environment variables for OCSP services:"
echo "    KMS_TRUSTSTORE_PATH=file:$DIR/truststore.p12"
echo "    KMS_TRUSTSTORE_PASSWORD=changeme"
echo "    KMS_KEYSTORE_PATH=file:$DIR/keystore.p12"
echo "    KMS_KEYSTORE_PASSWORD=changeme"
echo ""
echo "  KMS server TLS (when enabling TLS on mock KMS):"
echo "    Copy $DIR/kms-server.p12 to KMS/src/main/resources/keystore/"
echo ""
echo "  ⚠  Change all passwords before using in a shared environment!"
