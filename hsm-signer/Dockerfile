# Stage 1: Compile native pkcs11j JNI library, protobuf stubs, and Spring Boot gRPC service
FROM maven:3.9-eclipse-temurin-25 AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY pkcs11j /workspace/pkcs11j
RUN mvn -f /workspace/pkcs11j/pom.xml install -DskipTests --batch-mode

COPY hsm-signer-proto /workspace/hsm-signer-proto
RUN mvn -f /workspace/hsm-signer-proto/pom.xml install -DskipTests --batch-mode

COPY hsm-signer/pom.xml /workspace/hsm-signer/pom.xml
COPY hsm-signer/src /workspace/hsm-signer/src
RUN mvn -f /workspace/hsm-signer/pom.xml package -DskipTests --batch-mode

# Stage 2: Runtime image with SoftHSM2 + JDK 25
FROM eclipse-temurin:25-jdk-jammy

RUN apt-get update && apt-get install -y --no-install-recommends \
    softhsm2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /workspace/hsm-signer/target/hsm-signer-*.jar /app/app.jar

ENV SOFTHSM2_CONF=/etc/softhsm2/softhsm2.conf
ENV HSM_PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so

EXPOSE 9090 9091

ENTRYPOINT ["java", \
  "--enable-native-access=ALL-UNNAMED", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "/app/app.jar"]

