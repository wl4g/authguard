ARG GO_IMAGE=registry.cn-shenzhen.aliyuncs.com/wl4g/golang:1.26-alpine

FROM ${GO_IMAGE} AS builder
WORKDIR /workspace
COPY src/adapters/golang ./src/adapters/golang
COPY use-cases/customer-growth-job-service/e2e/deploy/biz-golang-sqlx-service ./use-cases/customer-growth-job-service/e2e/deploy/biz-golang-sqlx-service
WORKDIR /workspace/use-cases/customer-growth-job-service/e2e/deploy/biz-golang-sqlx-service
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/customer-growth-job ./cmd/server

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system nonroot \
    && useradd --system --gid nonroot --no-create-home nonroot
COPY --from=builder --chown=nonroot:nonroot /out/customer-growth-job /usr/local/bin/customer-growth-job
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/customer-growth-job"]
