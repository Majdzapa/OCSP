FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /workspace

# KMS is a standalone Maven project (no parent pom needed for build),
# but we copy the parent pom so annotationProcessorPaths can reference it
COPY pom.xml      ./pom.xml
COPY KMS/pom.xml  ./KMS/pom.xml
COPY KMS/src      ./KMS/src

RUN mvn -f KMS/pom.xml package -DskipTests --no-transfer-progress

FROM eclipse-temurin:21-jre-jammy
LABEL org.opencontainers.image.title="KMS Mock"
LABEL org.opencontainers.image.description="Lightweight mock Key Management Service for OCSP signing (dev only)"

RUN groupadd -r ocsp && useradd -r -g ocsp ocsp
USER ocsp
WORKDIR /app
COPY --from=build /workspace/KMS/target/kms-mock-*.jar app.jar

EXPOSE 8085
ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", \
            "-Djava.security.egd=file:/dev/./urandom", \
            "-jar", "app.jar"]
