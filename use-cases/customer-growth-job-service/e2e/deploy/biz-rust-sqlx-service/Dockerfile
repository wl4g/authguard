ARG RUST_BUILDER_IMAGE=registry.cn-shenzhen.aliyuncs.com/wl4g/authguard-rust-builder:1.94-bookworm
ARG RUNTIME_IMAGE=registry.cn-shenzhen.aliyuncs.com/wl4g/authguard-runtime:nonroot

FROM ${RUST_BUILDER_IMAGE} AS builder
WORKDIR /workspace
COPY rust-toolchain.toml ./
RUN cargo --version
COPY . .
RUN cargo build --release --manifest-path use-cases/customer-growth-job-service/e2e/deploy/biz-rust-sqlx-service/Cargo.toml --bin authguard-customer-growth-job-rust-service

FROM ${RUNTIME_IMAGE}
COPY --from=builder /workspace/use-cases/customer-growth-job-service/e2e/deploy/biz-rust-sqlx-service/target/release/authguard-customer-growth-job-rust-service /usr/local/bin/e2e-authguard-rust-sqlx
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/e2e-authguard-rust-sqlx"]
