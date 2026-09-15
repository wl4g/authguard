# Mirrors the local-validator image recipe used by the Flowgent development stack.
# The E2E runner normally consumes the prebuilt Aliyun image declared in Helm.
FROM registry.cn-shenzhen.aliyuncs.com/wl4g/rust:1.93-slim

RUN apt-get update && apt-get install -y --no-install-recommends bzip2 \
    && rm -rf /var/lib/apt/lists/*

COPY solana-release.tar.bz2 /tmp/solana.tar.bz2
RUN mkdir -p /opt/solana \
    && tar -xjf /tmp/solana.tar.bz2 -C /opt/solana \
    && rm /tmp/solana.tar.bz2

ENV PATH="/opt/solana/solana-release/bin:${PATH}"

EXPOSE 8899 8900
ENTRYPOINT ["sh", "-c"]
CMD ["exec solana-test-validator --bind-address=\"$(hostname -i | cut -d' ' -f1)\" --rpc-port=8899 --faucet-port=8900 --ledger=/tmp/solana-ledger --reset --quiet --limit-ledger-size=1000 --faucet-sol=10 --rpc-pubsub-max-active-subscriptions=16 --rpc-pubsub-notification-threads=0 --rpc-pubsub-worker-threads=1 --rpc-pubsub-queue-capacity-items=32 --rpc-pubsub-queue-capacity-bytes=1048576"]
