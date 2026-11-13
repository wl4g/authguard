ARG DEBIAN_IMAGE
ARG RUST_BUILDER_IMAGE

FROM ${RUST_BUILDER_IMAGE} AS builder
ARG DEBIAN_MIRROR=http://deb.debian.org
RUN sed -i "s|http://deb.debian.org|${DEBIAN_MIRROR}|g" /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends build-essential libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY rust-toolchain.toml ./
RUN cargo --version
COPY . .
ARG CARGO_BUILD_JOBS=2
ARG TARGETARCH
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,id=authguard-growth-rust-${TARGETARCH}-target,sharing=locked,target=/build/target \
    export CARGO_TARGET_DIR=/build/target; \
    if [ "$(du -sk /build/target | cut -f1)" -gt 20971520 ]; then cargo clean; fi; \
    cargo build --release --manifest-path use-cases/customer-growth-job-service/deploy/biz-rust-sqlx-service/source/Cargo.toml --bin authguard-customer-growth-job-rust-service \
    && install -D -m 0755 /build/target/release/authguard-customer-growth-job-rust-service /out/customer-growth-job

FROM ${DEBIAN_IMAGE} AS runtime
ARG DEBIAN_MIRROR=http://deb.debian.org
RUN sed -i "s|http://deb.debian.org|${DEBIAN_MIRROR}|g" /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3t64 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system nonroot \
    && useradd --system --gid nonroot --no-create-home nonroot
COPY --from=builder --chown=nonroot:nonroot /out/customer-growth-job /usr/local/bin/e2e-authguard-rust-sqlx
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/e2e-authguard-rust-sqlx"]
