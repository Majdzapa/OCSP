# Stage 1: Build the Spring Boot JAR inside Docker (no host Maven/JDK 25 required)
FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /build
COPY ocsp-responder/pom.xml ./pom.xml
COPY ocsp-responder/src ./src
RUN mvn package -DskipTests --batch-mode

# Stage 2: Runtime image with SoftHSM2 PKCS#11 library
FROM eclipse-temurin:25-jdk-jammy

RUN apt-get update && apt-get install -y --no-install-recommends \
    softhsm2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /build/target/ocsp-responder-*.jar /app/app.jar

ENV SOFTHSM2_CONF=/etc/softhsm2/softhsm2.conf
ENV HSM_PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so

ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "/app/app.jar"]
