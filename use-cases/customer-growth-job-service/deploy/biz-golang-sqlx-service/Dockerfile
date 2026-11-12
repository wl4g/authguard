ARG DEBIAN_IMAGE
ARG GO_IMAGE

FROM ${GO_IMAGE} AS builder
WORKDIR /workspace
COPY src/adapters/golang ./src/adapters/golang
COPY use-cases/customer-growth-job-service/deploy/biz-golang-sqlx-service/source ./use-cases/customer-growth-job-service/deploy/biz-golang-sqlx-service/source
WORKDIR /workspace/use-cases/customer-growth-job-service/deploy/biz-golang-sqlx-service/source
ARG GOPROXY=https://proxy.golang.org,direct
ARG GOMAXPROCS=2
ARG GOFLAGS=-p=2
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/customer-growth-job ./cmd/server

FROM ${DEBIAN_IMAGE} AS runtime
ARG DEBIAN_MIRROR=http://deb.debian.org
RUN sed -i "s|http://deb.debian.org|${DEBIAN_MIRROR}|g" /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system nonroot \
    && useradd --system --gid nonroot --no-create-home nonroot
COPY --from=builder --chown=nonroot:nonroot /out/customer-growth-job /usr/local/bin/customer-growth-job
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/customer-growth-job"]
