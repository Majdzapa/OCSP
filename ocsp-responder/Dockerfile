FROM eclipse-temurin:25-jdk-jammy

# Install SoftHSM2 runtime library (libsofthsm2.so) so SunPKCS11 can access the HSM tokens
RUN apt-get update && apt-get install -y --no-install-recommends \
    softhsm2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy packaged Spring Boot application directly
COPY ocsp-responder/target/ocsp-responder-*.jar /app/app.jar

ENV SOFTHSM2_CONF=/etc/softhsm2/softhsm2.conf
ENV HSM_PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so

# No shell script entrypoint: directly run the Java application configured via application.properties/yml
ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "/app/app.jar"]
