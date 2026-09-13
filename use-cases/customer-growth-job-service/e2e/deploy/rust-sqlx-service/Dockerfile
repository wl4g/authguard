FROM registry.cn-shenzhen.aliyuncs.com/wl4g/authguard-rust-builder:1.94-bookworm AS builder
WORKDIR /workspace
COPY . .
RUN cargo build --release --locked --package authguard-customer-growth-job-rust-service --bin authguard-customer-growth-job-rust-service

FROM registry.cn-shenzhen.aliyuncs.com/wl4g/authguard-runtime:nonroot
COPY --from=builder /workspace/target/release/authguard-customer-growth-job-rust-service /usr/local/bin/e2e-authguard-rust-sqlx
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/e2e-authguard-rust-sqlx"]
