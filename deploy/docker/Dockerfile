FROM registry.cn-shenzhen.aliyuncs.com/wl4g/authguard-rust-builder:1.94-bookworm AS builder
WORKDIR /workspace
COPY rust-toolchain.toml ./
RUN cargo --version
COPY . .
ARG AUTHGUARD_CARGO_FEATURES=""
RUN if [ -n "${AUTHGUARD_CARGO_FEATURES}" ]; then \
      cargo build --locked --release -p authguard-cmd --bin authguard \
        --features "${AUTHGUARD_CARGO_FEATURES}"; \
    else \
      cargo build --locked --release -p authguard-cmd --bin authguard; \
    fi

FROM registry.cn-shenzhen.aliyuncs.com/wl4g/authguard-runtime:nonroot
COPY --from=builder /workspace/target/release/authguard /usr/local/bin/authguard
USER nonroot:nonroot
EXPOSE 8080 8081 8082 9090 9091
ENTRYPOINT ["/usr/local/bin/authguard"]
CMD ["authz"]
