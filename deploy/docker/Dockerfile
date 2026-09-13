FROM registry.cn-shenzhen.aliyuncs.com/wl4g/authguard-rust-builder:1.94-bookworm AS builder
WORKDIR /workspace
COPY . .
RUN cargo build --locked --release -p authguard-cmd --bin authguard

FROM registry.cn-shenzhen.aliyuncs.com/wl4g/authguard-runtime:nonroot
COPY --from=builder /workspace/target/release/authguard /usr/local/bin/authguard
USER nonroot:nonroot
EXPOSE 8080 8081 8082 9091
ENTRYPOINT ["/usr/local/bin/authguard"]
CMD ["authz"]
