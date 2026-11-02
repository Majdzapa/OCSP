FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /workspace

# Copy parent pom + all child module poms so the reactor can resolve
COPY pom.xml                       ./pom.xml
COPY ocsp-responder/pom.xml        ./ocsp-responder/pom.xml
COPY ocsp-sync-service/pom.xml     ./ocsp-sync-service/pom.xml
COPY ocsp-admin-api/pom.xml        ./ocsp-admin-api/pom.xml
COPY ocsp-auth/pom.xml             ./ocsp-auth/pom.xml

# Pre-warm dependency cache (fast layer if poms didn't change)
RUN mvn -f pom.xml -pl ocsp-responder dependency:resolve --no-transfer-progress -q

COPY ocsp-responder/src ./ocsp-responder/src
RUN mvn -f pom.xml -pl ocsp-responder package -DskipTests --no-transfer-progress

# ── Runtime image ──────────────────────────────────────────────
FROM eclipse-temurin:21-jre-jammy
LABEL org.opencontainers.image.title="OCSP Responder"
LABEL org.opencontainers.image.description="RFC 6960 OCSP Responder for Incert Private CA"

RUN groupadd -r ocsp && useradd -r -g ocsp ocsp
USER ocsp
WORKDIR /app
COPY --from=build /workspace/ocsp-responder/target/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", \
            "-Djava.security.egd=file:/dev/./urandom", \
            "-jar", "app.jar"]
