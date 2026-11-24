# Stage 1: Pure Java Maven build of ocsp-responder (uses Maven Central org.xipki:ipkcs11wrapper)
FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /build

COPY ocsp-responder/pom.xml ./pom.xml
COPY ocsp-responder/src ./src
RUN mvn package -DskipTests --batch-mode && \
    mkdir -p /opt/pkcs11j && \
    ARCH="$(uname -m)" && \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
      WRAPPER_ENTRY="natives/unix/linux-aarch64/release/libpkcs11wrapper.so"; \
    else \
      WRAPPER_ENTRY="natives/unix/linux-x86_64/release/libpkcs11wrapper.so"; \
    fi && \
    (cd /tmp && jar xf /root/.m2/repository/org/xipki/ipkcs11wrapper/1.0.9/ipkcs11wrapper-1.0.9.jar "$WRAPPER_ENTRY" && \
     cp "/tmp/$WRAPPER_ENTRY" /opt/pkcs11j/libpkcs11wrapper.so && chmod 755 /opt/pkcs11j/libpkcs11wrapper.so)

# Stage 2: Runtime image with SoftHSM2 PKCS#11 library and pre-staged JNI wrapper
FROM eclipse-temurin:25-jdk-jammy

RUN apt-get update && apt-get install -y --no-install-recommends \
    softhsm2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /opt/pkcs11j/libpkcs11wrapper.so /opt/pkcs11j/libpkcs11wrapper.so
COPY --from=build /build/target/ocsp-responder-*.jar /app/app.jar

ENV SOFTHSM2_CONF=/etc/softhsm2/softhsm2.conf

ENTRYPOINT ["java", \
  "--enable-native-access=ALL-UNNAMED", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "/app/app.jar"]
