# ===================================================================
# CyberShield Backend - Multi-stage Production Container
# Base: Eclipse Temurin Java 21 (glibc Ubuntu Jammy)
# Required for native Microsoft ONNX Runtime Java inference
# ===================================================================

# -------------------------------------------------------------------
# Stage 1: Build & Package the Fat JAR
# -------------------------------------------------------------------
FROM eclipse-temurin:21-jdk-jammy AS builder
WORKDIR /workspace

# Copy build descriptor and wrapper
COPY pom.xml mvnw ./
COPY .mvn .mvn

# Make wrapper executable and pre-fetch dependencies (cached unless pom.xml changes)
RUN chmod +x ./mvnw && ./mvnw dependency:go-offline -B || true

# Copy source code and embedded ONNX model
COPY src src

# Build and package the production archive
RUN ./mvnw clean package -DskipTests -B

# -------------------------------------------------------------------
# Stage 2: Minimal Production JRE Runtime
# -------------------------------------------------------------------
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app

# Create unprivileged system group and user
RUN groupadd -r cybershield && useradd -r -g cybershield cybershield

# Copy fat JAR from build stage
COPY --from=builder /workspace/target/cybershield-backend-1.0.0.jar app.jar
RUN chown -R cybershield:cybershield /app

# Switch to non-root user
USER cybershield

# Railway assigns dynamic listening port via PORT environment variable (default 8080)
EXPOSE 8080
ENV PORT=8080
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0"

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar --server.port=${PORT}"]
