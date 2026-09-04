FROM registry.cn-shenzhen.aliyuncs.com/wl4g/maven:3.9.9-eclipse-temurin-17 AS builder
ARG MAVEN_PROXY_HOST
ARG MAVEN_PROXY_PORT
WORKDIR /workspace
COPY use-cases/customer-growth-job-service/e2e/config/maven-settings.xml /workspace/maven-settings.xml
RUN if [ -n "${MAVEN_PROXY_HOST:-}" ]; then \
        sed \
          -e "s/@MAVEN_PROXY_HOST@/${MAVEN_PROXY_HOST}/g" \
          -e "s/@MAVEN_PROXY_PORT@/${MAVEN_PROXY_PORT}/g" \
          /workspace/maven-settings.xml > /workspace/maven-settings-active.xml; \
    fi
COPY src/adapters/java /workspace/adapter
RUN set -eu; \
    settings_args=""; \
    if [ -n "${MAVEN_PROXY_HOST:-}" ]; then \
        settings_args="-s /workspace/maven-settings-active.xml"; \
    fi; \
    mvn -q ${settings_args} -f /workspace/adapter/pom.xml -DskipTests install
COPY use-cases/customer-growth-job-service/e2e/deploy/springboot-jpa-service /workspace/service
RUN set -eu; \
    settings_args=""; \
    if [ -n "${MAVEN_PROXY_HOST:-}" ]; then \
        settings_args="-s /workspace/maven-settings-active.xml"; \
    fi; \
    mvn -q ${settings_args} -f /workspace/service/pom.xml -DskipTests package

FROM registry.cn-shenzhen.aliyuncs.com/wl4g/eclipse-temurin:17-jre
WORKDIR /app
COPY --from=builder /workspace/service/target/authguard-customer-growth-job-springboot-jpa-service-0.1.0.jar /app/service.jar
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=70", "-jar", "/app/service.jar"]
