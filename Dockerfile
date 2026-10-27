# ===================================================================
# CyberShield Backend - Root Multi-stage Production Container
# Base: Eclipse Temurin Java 21 (glibc Ubuntu Jammy)
# Required for native Microsoft ONNX Runtime Java inference
# ===================================================================

FROM eclipse-temurin:21-jdk-jammy AS builder
WORKDIR /workspace

# Copy backend maven configuration and wrapper
COPY backend/pom.xml backend/mvnw ./
COPY backend/.mvn ./.mvn

# Pre-fetch dependencies
RUN chmod +x ./mvnw && ./mvnw dependency:go-offline -B || true

# Copy backend source code and ONNX model
COPY backend/src ./src

# Build production JAR
RUN ./mvnw clean package -DskipTests -B

# Runtime stage
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app

RUN groupadd -r cybershield && useradd -r -g cybershield cybershield

COPY --from=builder /workspace/target/cybershield-backend-1.0.0.jar app.jar
RUN chown -R cybershield:cybershield /app

USER cybershield

EXPOSE 8080
ENV PORT=8080
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0"

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar --server.port=${PORT}"]
