FROM ubuntu:24.04

# Install SoftHSM2, OpenSC, OpenSSL, curl
RUN apt-get update && apt-get install -y --no-install-recommends \
    softhsm2 \
    opensc \
    openssl \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Configure default SoftHSM directories
RUN mkdir -p /etc/softhsm2 /var/lib/softhsm/tokens /data/pki /scripts \
    && echo "directories.tokendir = /var/lib/softhsm/tokens" > /etc/softhsm2/softhsm2.conf \
    && echo "objectstore.backend = file" >> /etc/softhsm2/softhsm2.conf \
    && echo "log.level = INFO" >> /etc/softhsm2/softhsm2.conf

COPY hsm/init-hsm.sh /scripts/init-hsm.sh
RUN chmod +x /scripts/init-hsm.sh

ENV SOFTHSM2_CONF=/etc/softhsm2/softhsm2.conf
ENV HSM_TOKEN_LABEL=ocsp-signing
ENV HSM_PIN=1234
ENV HSM_SO_PIN=12345678
ENV HSM_KEY_LABEL=ocsp-signing-key
ENV HSM_PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so
ENV PKI_DIR=/data/pki

WORKDIR /var/lib/softhsm

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=6 \
  CMD pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --token-label "${HSM_TOKEN_LABEL}" --login --pin "${HSM_PIN}" --list-objects 2>/dev/null | grep -q "${HSM_KEY_LABEL}" || exit 1

ENTRYPOINT ["/scripts/init-hsm.sh"]

