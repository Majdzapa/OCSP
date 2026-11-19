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
RUN mkdir -p /etc/softhsm2 /var/lib/softhsm/tokens /scripts \
    && echo "directories.tokendir = /var/lib/softhsm/tokens" > /etc/softhsm2/softhsm2.conf \
    && echo "objectstore.backend = file" >> /etc/softhsm2/softhsm2.conf \
    && echo "log.level = INFO" >> /etc/softhsm2/softhsm2.conf

COPY hsm/init-hsm.sh /scripts/init-hsm.sh
RUN chmod +x /scripts/init-hsm.sh

ENV SOFTHSM2_CONF=/etc/softhsm2/softhsm2.conf
# Default values only — override all of these via environment variables in docker-compose or Kubernetes secrets.
# Never ship production PIN values as Dockerfile defaults.
ENV HSM_TOKEN_LABEL=ocsp-signing
ENV HSM_PIN=changeme-pin
ENV HSM_SO_PIN=changeme-sopin
ENV HSM_PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so

WORKDIR /var/lib/softhsm

# Healthy once the token exists (keys are created later by the user through the responder)
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=6 \
  CMD softhsm2-util --show-slots | grep -q "Label:.*${HSM_TOKEN_LABEL}" || exit 1

ENTRYPOINT ["/scripts/init-hsm.sh"]

