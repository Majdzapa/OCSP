#!/usr/bin/env bash
# =============================================================================
# certs/gen-rabbitmq-certs.sh
# Generates Certificate Authority, Server Certificate (with SAN),
# Client Certificate, and Java PKCS#12 Keystores/Truststores for RabbitMQ mTLS.
# =============================================================================
set -euo pipefail

PASS="changeme"
DIR="$(cd "$(dirname "$0")" && pwd)/rabbitmq"
mkdir -p "$DIR"

echo "🔐 Generating RabbitMQ mTLS certificates in $DIR..."

# -----------------------------------------------------------------------------
# 1. RabbitMQ Certificate Authority (CA)
# -----------------------------------------------------------------------------
echo "  ➜ Generating RabbitMQ CA..."
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$DIR/ca-key.pem" \
    -out "$DIR/ca.pem" \
    -days 3650 \
    -subj "/CN=Incert-RabbitMQ-CA/O=Incert/C=FR" 2>/dev/null
chmod 644 "$DIR/ca.pem" "$DIR/ca-key.pem"

# -----------------------------------------------------------------------------
# 2. RabbitMQ Broker / Server Certificate
# -----------------------------------------------------------------------------
echo "  ➜ Generating RabbitMQ Broker Server certificate (SAN: rabbitmq, localhost, 127.0.0.1)..."
openssl req -newkey rsa:2048 -nodes \
    -keyout "$DIR/server-key.pem" \
    -out "$DIR/server.csr" \
    -subj "/CN=rabbitmq/O=Incert/C=FR" 2>/dev/null

cat <<EOF > "$DIR/server-ext.cnf"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = rabbitmq
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in "$DIR/server.csr" \
    -CA "$DIR/ca.pem" -CAkey "$DIR/ca-key.pem" -CAcreateserial \
    -out "$DIR/server-cert.pem" -days 730 \
    -extfile "$DIR/server-ext.cnf" 2>/dev/null
chmod 644 "$DIR/server-cert.pem" "$DIR/server-key.pem"
rm -f "$DIR/server.csr" "$DIR/server-ext.cnf"

# -----------------------------------------------------------------------------
# 3. RabbitMQ Client Certificate (for KMS Simulator & OCSP Responder)
# -----------------------------------------------------------------------------
echo "  ➜ Generating RabbitMQ Client certificate (CN=rabbitmq-client)..."
openssl req -newkey rsa:2048 -nodes \
    -keyout "$DIR/client-key.pem" \
    -out "$DIR/client.csr" \
    -subj "/CN=rabbitmq-client/O=Incert/C=FR" 2>/dev/null

cat <<EOF > "$DIR/client-ext.cnf"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in "$DIR/client.csr" \
    -CA "$DIR/ca.pem" -CAkey "$DIR/ca-key.pem" -CAcreateserial \
    -out "$DIR/client-cert.pem" -days 730 \
    -extfile "$DIR/client-ext.cnf" 2>/dev/null
chmod 644 "$DIR/client-cert.pem" "$DIR/client-key.pem"
rm -f "$DIR/client.csr" "$DIR/client-ext.cnf"

# -----------------------------------------------------------------------------
# 4. PKCS#12 Client Keystore (contains client cert + private key + CA chain)
# -----------------------------------------------------------------------------
echo "  ➜ Packaging PKCS#12 Client Keystore..."
rm -f "$DIR/client-keystore.p12"
openssl pkcs12 -export \
    -in "$DIR/client-cert.pem" \
    -inkey "$DIR/client-key.pem" \
    -certfile "$DIR/ca.pem" \
    -name rabbitmq-client \
    -out "$DIR/client-keystore.p12" \
    -passout "pass:$PASS"
chmod 644 "$DIR/client-keystore.p12"

# -----------------------------------------------------------------------------
# 5. PKCS#12 Client Truststore (contains CA certificate)
# -----------------------------------------------------------------------------
echo "  ➜ Packaging PKCS#12 Client Truststore..."
rm -f "$DIR/client-truststore.p12"
# Use keytool inside container or keytool if available, fallback to openssl/python
if command -v keytool >/dev/null 2>&1; then
    keytool -importcert -alias rabbitmq-ca \
        -file "$DIR/ca.pem" \
        -keystore "$DIR/client-truststore.p12" \
        -storetype PKCS12 \
        -storepass "$PASS" \
        -noprompt 2>/dev/null
else
    docker exec -i ocsp-responder keytool -importcert -alias rabbitmq-ca \
        -file - \
        -keystore /tmp/generated-truststore.p12 \
        -storetype PKCS12 \
        -storepass "$PASS" \
        -noprompt < "$DIR/ca.pem" 2>/dev/null
    docker cp ocsp-responder:/tmp/generated-truststore.p12 "$DIR/client-truststore.p12"
    docker exec ocsp-responder rm -f /tmp/generated-truststore.p12
fi
chmod 644 "$DIR/client-truststore.p12"

# -----------------------------------------------------------------------------
# 6. Untrusted Client Certificate (for rejection testing)
# -----------------------------------------------------------------------------
echo "  ➜ Generating untrusted client certificate (rogue CA)..."
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$DIR/untrusted-ca-key.pem" \
    -out "$DIR/untrusted-ca.pem" \
    -days 365 \
    -subj "/CN=Rogue-Untrusted-CA/O=Attacker/C=XX" 2>/dev/null

openssl req -newkey rsa:2048 -nodes \
    -keyout "$DIR/untrusted-client-key.pem" \
    -out "$DIR/untrusted.csr" \
    -subj "/CN=untrusted-client/O=Attacker/C=XX" 2>/dev/null

openssl x509 -req -in "$DIR/untrusted.csr" \
    -CA "$DIR/untrusted-ca.pem" -CAkey "$DIR/untrusted-ca-key.pem" -CAcreateserial \
    -out "$DIR/untrusted-client-cert.pem" -days 365 2>/dev/null
chmod 644 "$DIR/untrusted-client-cert.pem" "$DIR/untrusted-client-key.pem"
rm -f "$DIR/untrusted.csr" "$DIR/untrusted-ca-key.pem" "$DIR/untrusted-ca.pem" "$DIR"/*.srl

echo "✅ RabbitMQ mTLS certificates successfully generated in $DIR"
