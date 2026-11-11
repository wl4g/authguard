ARG MAVEN_IMAGE
ARG JAVA_IMAGE

FROM ${MAVEN_IMAGE} AS builder
ARG MAVEN_PROXY_HOST
ARG MAVEN_PROXY_PORT
WORKDIR /workspace
COPY use-cases/customer-growth-job-service/util/maven/settings.xml /workspace/maven/settings.xml
RUN if [ -n "${MAVEN_PROXY_HOST:-}" ]; then \
        sed \
          -e "s/@MAVEN_PROXY_HOST@/${MAVEN_PROXY_HOST}/g" \
          -e "s/@MAVEN_PROXY_PORT@/${MAVEN_PROXY_PORT}/g" \
          /workspace/maven/settings.xml > /workspace/maven-settings-active.xml; \
    fi
COPY src/adapters/java /workspace/adapter
RUN set -eu; \
    settings_args=""; \
    if [ -n "${MAVEN_PROXY_HOST:-}" ]; then \
        settings_args="-s /workspace/maven-settings-active.xml"; \
    fi; \
    mvn -q ${settings_args} -f /workspace/adapter/pom.xml -DskipTests install
COPY use-cases/customer-growth-job-service/deploy/biz-springboot-jpa-service/source /workspace/service
RUN set -eu; \
    settings_args=""; \
    if [ -n "${MAVEN_PROXY_HOST:-}" ]; then \
        settings_args="-s /workspace/maven-settings-active.xml"; \
    fi; \
    mvn -q ${settings_args} -f /workspace/service/pom.xml -DskipTests package

FROM ${JAVA_IMAGE}
WORKDIR /app
COPY --from=builder /workspace/service/target/authguard-customer-growth-job-biz-springboot-jpa-service-0.1.0.jar /app/service.jar
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=70", "-jar", "/app/service.jar"]
