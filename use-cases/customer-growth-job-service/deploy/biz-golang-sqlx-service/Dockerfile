ARG DEBIAN_IMAGE
ARG GO_IMAGE

FROM ${GO_IMAGE} AS builder
WORKDIR /workspace
COPY src/adapters/golang ./src/adapters/golang
COPY use-cases/customer-growth-job-service/deploy/biz-golang-sqlx-service/source ./use-cases/customer-growth-job-service/deploy/biz-golang-sqlx-service/source
WORKDIR /workspace/use-cases/customer-growth-job-service/deploy/biz-golang-sqlx-service/source
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/customer-growth-job ./cmd/server

FROM ${DEBIAN_IMAGE} AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system nonroot \
    && useradd --system --gid nonroot --no-create-home nonroot
COPY --from=builder --chown=nonroot:nonroot /out/customer-growth-job /usr/local/bin/customer-growth-job
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/customer-growth-job"]
