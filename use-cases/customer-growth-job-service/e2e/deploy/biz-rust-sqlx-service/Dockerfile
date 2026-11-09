ARG RUST_BUILDER_IMAGE=registry.cn-shenzhen.aliyuncs.com/wl4g/rust:1.99.1-slim

FROM ${RUST_BUILDER_IMAGE} AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY rust-toolchain.toml ./
RUN cargo --version
COPY . .
RUN cargo build --release --manifest-path use-cases/customer-growth-job-service/e2e/deploy/biz-rust-sqlx-service/Cargo.toml --bin authguard-customer-growth-job-rust-service

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3t64 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system nonroot \
    && useradd --system --gid nonroot --no-create-home nonroot
COPY --from=builder --chown=nonroot:nonroot /workspace/use-cases/customer-growth-job-service/e2e/deploy/biz-rust-sqlx-service/target/release/authguard-customer-growth-job-rust-service /usr/local/bin/e2e-authguard-rust-sqlx
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/e2e-authguard-rust-sqlx"]
