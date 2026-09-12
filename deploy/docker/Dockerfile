FROM registry.cn-shenzhen.aliyuncs.com/wl4g/authguard-rust-builder:1.94-bookworm AS builder
WORKDIR /workspace
COPY . .
RUN cargo build --locked --release \
    -p authguard-authn --bin authguard-authn \
    -p authguard-authz --bin authguard-authz

FROM registry.cn-shenzhen.aliyuncs.com/wl4g/authguard-runtime:nonroot
COPY --from=builder /workspace/target/release/authguard-authz /usr/local/bin/authguard-authz
COPY --from=builder /workspace/target/release/authguard-authn /usr/local/bin/authguard-authn
USER nonroot:nonroot
EXPOSE 8080 8081 8082 9091
ENTRYPOINT ["/usr/local/bin/authguard-authz"]
