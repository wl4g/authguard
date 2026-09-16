# Pinned official Agave release; override the base URL for an internal mirror.
ARG RUST_IMAGE=registry.cn-shenzhen.aliyuncs.com/wl4g/rust:1.93-slim
FROM ${RUST_IMAGE} AS downloader

ARG TARGETARCH=amd64
ARG AGAVE_VERSION=3.1.14
ARG AGAVE_RELEASE_BASE_URL=https://github.com/anza-xyz/agave/releases/download
ARG AGAVE_AMD64_SHA256=06f97c065cc977cbec2f13ffc9bc9d3b92fef485431fcb370a269de69532ef51

RUN apt-get update \
    && apt-get install -y --no-install-recommends bzip2 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && test "${TARGETARCH}" = amd64 \
       || { echo "Agave v${AGAVE_VERSION} has no supported ${TARGETARCH} Linux release asset" >&2; exit 1; } \
    && archive=solana-release-x86_64-unknown-linux-gnu.tar.bz2 \
    && curl --fail --location --proto '=https' --tlsv1.2 --retry 5 \
         "${AGAVE_RELEASE_BASE_URL}/v${AGAVE_VERSION}/${archive}" \
         --output /tmp/solana-release.tar.bz2 \
    && echo "${AGAVE_AMD64_SHA256}  /tmp/solana-release.tar.bz2" \
       | sha256sum --check --strict \
    && mkdir -p /opt/solana \
    && tar -xjf /tmp/solana-release.tar.bz2 -C /opt/solana

FROM ${RUST_IMAGE}

COPY --from=downloader /opt/solana /opt/solana
ENV PATH="/opt/solana/solana-release/bin:${PATH}"

EXPOSE 8899 8900
ENTRYPOINT ["sh", "-c"]
CMD ["exec solana-test-validator --bind-address=\"$(hostname -i | cut -d' ' -f1)\" --rpc-port=8899 --faucet-port=8900 --ledger=/tmp/solana-ledger --quiet --limit-ledger-size=1000 --faucet-sol=10 --rpc-pubsub-max-active-subscriptions=16 --rpc-pubsub-notification-threads=0 --rpc-pubsub-worker-threads=1 --rpc-pubsub-queue-capacity-items=32 --rpc-pubsub-queue-capacity-bytes=1048576"]
