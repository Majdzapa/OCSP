# Stage 1: Build React 18 Admin Console & Public OCSP Client (ocsp-console)
FROM node:20-alpine AS frontend-build
WORKDIR /app

COPY ocsp-console/package.json ocsp-console/yarn.lock ./
RUN yarn install --frozen-lockfile

COPY ocsp-console/ ./
ENV VITE_API_BASE_URL=""
ENV VITE_AUTH_BASE_URL=""
RUN yarn build

# Stage 2: Pure Java Maven build of ocsp-responder with embedded React SPA + Antora docs
FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /build

COPY ocsp-responder/pom.xml ./pom.xml
COPY ocsp-responder/src ./src

# Embed compiled React frontend under /console/** and Antora docs under /docs/**
RUN rm -rf ./src/main/resources/static/*
COPY --from=frontend-build /app/dist/ ./src/main/resources/static/console/
COPY build/site/ ./src/main/resources/static/docs/

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

# Stage 3: Runtime image with SoftHSM2 PKCS#11 library, pre-staged JNI wrapper, and unified JAR
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
 