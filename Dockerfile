# =========================
# BUILD STAGE
# =========================
FROM maven:3.9.9-eclipse-temurin-21-alpine AS build

WORKDIR /build

COPY pom.xml .
COPY .mvn .mvn
COPY mvnw .

RUN mvn -B -q dependency:go-offline

COPY src src
RUN mvn -B package -DskipTests


# =========================
# RUNTIME STAGE (DISTROLESS)
# =========================
FROM gcr.io/distroless/java21-debian12:nonroot

WORKDIR /app

# Copy jar
COPY --from=build /build/target/*.jar /app/app.jar

# Expose app port
EXPOSE 8080

# Distroless has no wget/curl, so healthcheck must be removed OR done externally.
# Recommended: use Kubernetes / ECS / ALB health checks instead.
# HEALTHCHECK disabled intentionally.

# JVM tuned for 1 GB RAM
ENTRYPOINT ["java","-XX:MaxRAMPercentage=70","-XX:InitialRAMPercentage=50","-XX:+UseSerialGC","-XX:+ExitOnOutOfMemoryError","-Djava.security.egd=file:/dev/./urandom","-jar","/app/app.jar"]
