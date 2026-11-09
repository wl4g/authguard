ARG RUST_BUILDER_IMAGE=registry.cn-shenzhen.aliyuncs.com/wl4g/rust:1.99.1-slim

FROM ${RUST_BUILDER_IMAGE} AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
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

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3t64 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system nonroot \
    && useradd --system --gid nonroot --no-create-home nonroot
COPY --from=builder --chown=nonroot:nonroot /workspace/target/release/authguard /usr/local/bin/authguard
RUN ["/usr/local/bin/authguard", "--version"]
USER nonroot:nonroot
EXPOSE 8080 8081 8082 9090 9091
ENTRYPOINT ["/usr/local/bin/authguard"]
CMD ["authz"]
