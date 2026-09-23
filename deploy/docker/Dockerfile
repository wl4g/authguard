ARG RUST_BUILDER_IMAGE=registry.cn-shenzhen.aliyuncs.com/wl4g/authguard-rust-builder:1.94-bookworm
ARG RUNTIME_IMAGE=registry.cn-shenzhen.aliyuncs.com/wl4g/authguard-runtime:nonroot

FROM ${RUST_BUILDER_IMAGE} AS builder
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

FROM ${RUNTIME_IMAGE}
COPY --from=builder /workspace/target/release/authguard /usr/local/bin/authguard
# Fail the image build immediately when an overridden runtime omits a native
# library required by the audited WebAuthn implementation (currently libssl3).
RUN ["/usr/local/bin/authguard", "--version"]
USER nonroot:nonroot
EXPOSE 8080 8081 8082 9090 9091
ENTRYPOINT ["/usr/local/bin/authguard"]
CMD ["authz"]
