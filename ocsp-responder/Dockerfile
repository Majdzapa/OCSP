FROM eclipse-temurin:25-jdk-jammy

# Install SoftHSM2, OpenSC, OpenSSL, curl
RUN apt-get update && apt-get install -y --no-install-recommends \
    softhsm2 \
    opensc \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Configure SoftHSM directories
RUN mkdir -p /etc/softhsm2 /var/lib/softhsm/tokens /data/pki /scripts \
    && echo "directories.tokendir = /var/lib/softhsm/tokens" > /etc/softhsm2/softhsm2.conf \
    && echo "objectstore.backend = file" >> /etc/softhsm2/softhsm2.conf \
    && echo "log.level = INFO" >> /etc/softhsm2/softhsm2.conf

WORKDIR /app

COPY scripts/init-softhsm.sh /scripts/init-softhsm.sh
COPY ocsp-responder/entrypoint.sh /app/entrypoint.sh
COPY ocsp-responder/target/ocsp-responder-*.jar /app/app.jar

RUN chmod +x /scripts/init-softhsm.sh /app/entrypoint.sh

ENV SOFTHSM2_CONF=/etc/softhsm2/softhsm2.conf
ENV HSM_PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "/app/app.jar"]

