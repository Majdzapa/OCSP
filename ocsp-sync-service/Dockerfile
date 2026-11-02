FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /workspace

COPY pom.xml                       ./pom.xml
COPY ocsp-responder/pom.xml        ./ocsp-responder/pom.xml
COPY ocsp-sync-service/pom.xml     ./ocsp-sync-service/pom.xml
COPY ocsp-admin-api/pom.xml        ./ocsp-admin-api/pom.xml
COPY ocsp-auth/pom.xml             ./ocsp-auth/pom.xml

RUN mvn -f pom.xml -pl ocsp-sync-service dependency:resolve --no-transfer-progress -q

COPY ocsp-sync-service/src ./ocsp-sync-service/src
RUN mvn -f pom.xml -pl ocsp-sync-service package -DskipTests --no-transfer-progress

FROM eclipse-temurin:21-jre-jammy
LABEL org.opencontainers.image.title="OCSP Sync Service"
LABEL org.opencontainers.image.description="RabbitMQ consumer and reconciliation job for OCSP status updates"

RUN groupadd -r ocsp && useradd -r -g ocsp ocsp
USER ocsp
WORKDIR /app
COPY --from=build /workspace/ocsp-sync-service/target/*.jar app.jar

EXPOSE 8081
ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", \
            "-Djava.security.egd=file:/dev/./urandom", \
            "-jar", "app.jar"]
