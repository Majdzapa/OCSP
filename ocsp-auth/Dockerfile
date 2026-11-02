FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /workspace

# Copy parent pom and all child module poms so the reactor can resolve
COPY pom.xml                       ./pom.xml
COPY ocsp-responder/pom.xml        ./ocsp-responder/pom.xml
COPY ocsp-sync-service/pom.xml     ./ocsp-sync-service/pom.xml
COPY ocsp-admin-api/pom.xml        ./ocsp-admin-api/pom.xml
COPY ocsp-auth/pom.xml             ./ocsp-auth/pom.xml

# Pre-warm the dependency cache for this module only
RUN mvn -f pom.xml -pl ocsp-auth dependency:resolve --no-transfer-progress -q

# Copy only this module's source
COPY ocsp-auth/src ./ocsp-auth/src

RUN mvn -f pom.xml -pl ocsp-auth package -DskipTests --no-transfer-progress

# ── Runtime image ──────────────────────────────────────────────
FROM eclipse-temurin:21-jre-jammy
LABEL org.opencontainers.image.title="OCSP Auth Server"
LABEL org.opencontainers.image.description="Spring Authorization Server — issues JWT tokens for the OCSP Admin Console"

RUN groupadd -r ocsp && useradd -r -g ocsp ocsp
USER ocsp
WORKDIR /app
COPY --from=build /workspace/ocsp-auth/target/ocsp-auth-*.jar app.jar

EXPOSE 9000
ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", \
            "-Djava.security.egd=file:/dev/./urandom", \
            "-jar", "app.jar"]
