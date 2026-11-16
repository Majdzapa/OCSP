# Stage 1: Build the Spring Boot JAR inside Docker (no host Maven/JDK 25 required)
FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /build
COPY ocsp-client/pom.xml ./pom.xml
COPY ocsp-client/src ./src
RUN mvn package -DskipTests --batch-mode

# Stage 2: Runtime image
FROM eclipse-temurin:25-jre-alpine

RUN apk add --no-cache curl

WORKDIR /app

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY --from=build /build/target/ocsp-client-*.jar /app/app.jar

RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8082

ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-Djava.security.egd=file:/dev/./urandom", "-jar", "/app/app.jar"]
