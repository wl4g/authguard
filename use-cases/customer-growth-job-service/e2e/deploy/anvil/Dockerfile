# Pinned official Foundry release; override the base URL for an internal mirror.
ARG RUST_IMAGE=registry.cn-shenzhen.aliyuncs.com/wl4g/rust:1.93-slim
FROM ${RUST_IMAGE} AS downloader

ARG TARGETARCH=amd64
ARG FOUNDRY_VERSION=1.7.1
ARG FOUNDRY_RELEASE_BASE_URL=https://github.com/foundry-rs/foundry/releases/download
ARG FOUNDRY_AMD64_SHA256=cf7e688ed0c4c48adffca788b496076e31060b67ac5afe1e43dbb5499c20c88b
ARG FOUNDRY_ARM64_SHA256=c8fe8fa09ae3aba2c81b510c6f9da3a9d468029b9580e690b245b3f0aea687ae

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && case "${TARGETARCH}" in \
         amd64) checksum="${FOUNDRY_AMD64_SHA256}" ;; \
         arm64) checksum="${FOUNDRY_ARM64_SHA256}" ;; \
         *) echo "unsupported Foundry architecture: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && archive="foundry_v${FOUNDRY_VERSION}_linux_${TARGETARCH}.tar.gz" \
    && curl --fail --location --proto '=https' --tlsv1.2 --retry 5 \
         "${FOUNDRY_RELEASE_BASE_URL}/v${FOUNDRY_VERSION}/${archive}" \
         --output /tmp/foundry.tar.gz \
    && echo "${checksum}  /tmp/foundry.tar.gz" | sha256sum --check --strict \
    && mkdir -p /opt/foundry \
    && tar -xzf /tmp/foundry.tar.gz -C /opt/foundry anvil \
    && chmod 0755 /opt/foundry/anvil

FROM ${RUST_IMAGE}

COPY --from=downloader /opt/foundry/anvil /usr/local/bin/anvil

EXPOSE 8545
ENTRYPOINT ["anvil"]
CMD ["--host", "0.0.0.0", "--port", "8545", "--accounts", "10", "--balance", "10000", "--chain-id", "31337"]
