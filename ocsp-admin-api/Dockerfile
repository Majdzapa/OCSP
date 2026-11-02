FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /workspace

COPY pom.xml                       ./pom.xml
COPY ocsp-responder/pom.xml        ./ocsp-responder/pom.xml
COPY ocsp-sync-service/pom.xml     ./ocsp-sync-service/pom.xml
COPY ocsp-admin-api/pom.xml        ./ocsp-admin-api/pom.xml
COPY ocsp-auth/pom.xml             ./ocsp-auth/pom.xml

RUN mvn -f pom.xml -pl ocsp-admin-api dependency:resolve --no-transfer-progress -q

COPY ocsp-admin-api/src ./ocsp-admin-api/src
RUN mvn -f pom.xml -pl ocsp-admin-api package -DskipTests --no-transfer-progress

FROM eclipse-temurin:21-jre-jammy
LABEL org.opencontainers.image.title="OCSP Admin API"
LABEL org.opencontainers.image.description="Management REST API for the OCSP subsystem"

RUN groupadd -r ocsp && useradd -r -g ocsp ocsp
USER ocsp
WORKDIR /app
COPY --from=build /workspace/ocsp-admin-api/target/*.jar app.jar

EXPOSE 8082
ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", \
            "-Djava.security.egd=file:/dev/./urandom", \
            "-jar", "app.jar"]
