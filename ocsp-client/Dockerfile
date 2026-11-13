FROM eclipse-temurin:25-jre-alpine

RUN apk add --no-cache curl

WORKDIR /app

# Non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY ocsp-client/target/ocsp-client-*.jar /app/app.jar

RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8082

ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-Djava.security.egd=file:/dev/./urandom", "-jar", "/app/app.jar"]
