# -------- BUILD STAGE --------
FROM maven:3.9.9-eclipse-temurin-21-jammy AS build
WORKDIR /app

COPY pom.xml .
COPY .mvn .mvn
COPY mvnw mvnw.cmd ./

RUN ./mvnw -B -q dependency:go-offline

COPY src src
RUN ./mvnw -B -q clean package -DskipTests

# -------- RUNTIME STAGE --------
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app

ENV JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+UseG1GC -XX:+ExitOnOutOfMemoryError"

COPY --from=build /app/target/Auth-App-Backend-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8081

ENTRYPOINT ["sh","-c","java $JAVA_OPTS -jar app.jar"]
