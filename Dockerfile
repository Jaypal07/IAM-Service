# =========================
# BUILD STAGE
# =========================
FROM maven:3.9.9-eclipse-temurin-21-alpine AS build

WORKDIR /build

COPY pom.xml .
COPY .mvn .mvn
RUN mvn -B -q dependency:go-offline

COPY src src
RUN mvn -B package -DskipTests


# =========================
# RUNTIME STAGE
# =========================
FROM eclipse-temurin:21-jre-alpine

# Create non root user
RUN addgroup -S spring && adduser -S spring -G spring

WORKDIR /app

COPY --from=build /build/target/*jar app.jar
RUN chown spring:spring app.jar

USER spring

EXPOSE 8081

# Lightweight healthcheck, no curl
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s \
  CMD wget -qO- http://localhost:8081/actuator/health | grep UP || exit 1

# JVM tuned for 1 GB RAM EC2
ENTRYPOINT ["java",
"-XX:MaxRAMPercentage=70",
"-XX:InitialRAMPercentage=50",
"-XX:+UseSerialGC",
"-XX:+ExitOnOutOfMemoryError",
"-Djava.security.egd=file:/dev/./urandom",
"-jar",
"/app/app.jar"]
