ARG GO_IMAGE=registry.cn-shenzhen.aliyuncs.com/wl4g/golang:1.26-alpine
ARG RUNTIME_IMAGE=registry.cn-shenzhen.aliyuncs.com/wl4g/authguard-runtime:nonroot

FROM ${GO_IMAGE} AS builder
WORKDIR /workspace
COPY src/adapters/golang ./src/adapters/golang
COPY use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service ./use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service
WORKDIR /workspace/use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/customer-growth-job ./cmd/server

FROM ${RUNTIME_IMAGE}
COPY --from=builder /out/customer-growth-job /usr/local/bin/customer-growth-job
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/customer-growth-job"]
