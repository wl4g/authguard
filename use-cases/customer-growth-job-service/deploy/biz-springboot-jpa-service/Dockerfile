ARG MAVEN_IMAGE
ARG JAVA_IMAGE

FROM ${MAVEN_IMAGE} AS builder
ARG MAVEN_PROXY_HOST
ARG MAVEN_PROXY_PORT
ARG MAVEN_MIRROR_URL=https://repo.maven.apache.org/maven2
WORKDIR /workspace
COPY use-cases/customer-growth-job-service/util/maven/settings.xml /workspace/maven/settings.xml
RUN set -eu; \
    proxy_active=false; \
    if [ -n "${MAVEN_PROXY_HOST:-}" ]; then proxy_active=true; fi; \
    sed \
      -e "s|@MAVEN_PROXY_HOST@|${MAVEN_PROXY_HOST:-127.0.0.1}|g" \
      -e "s|@MAVEN_PROXY_PORT@|${MAVEN_PROXY_PORT:-8080}|g" \
      -e "s|@MAVEN_PROXY_ACTIVE@|${proxy_active}|g" \
      -e "s|@MAVEN_MIRROR_URL@|${MAVEN_MIRROR_URL}|g" \
      /workspace/maven/settings.xml > /workspace/maven-settings-active.xml
COPY src/sdk/java /workspace/sdk
RUN --mount=type=cache,id=authguard-growth-maven,target=/root/.m2,sharing=locked \
    mvn -q -s /workspace/maven-settings-active.xml -f /workspace/sdk/pom.xml -Dmaven.test.skip=true install
COPY use-cases/customer-growth-job-service/deploy/biz-springboot-jpa-service/source /workspace/service
RUN --mount=type=cache,id=authguard-growth-maven,target=/root/.m2,sharing=locked \
    mvn -q -s /workspace/maven-settings-active.xml -f /workspace/service/pom.xml -Dmaven.test.skip=true package

FROM ${JAVA_IMAGE}
WORKDIR /app
COPY --from=builder /workspace/service/target/authguard-customer-growth-job-biz-springboot-jpa-service-0.1.0.jar /app/service.jar
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=70", "-jar", "/app/service.jar"]
