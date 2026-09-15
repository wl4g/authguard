# Mirrors the local-chain image recipe used by the Flowgent development stack.
# The E2E runner normally consumes the prebuilt Aliyun image declared in Helm.
FROM registry.cn-shenzhen.aliyuncs.com/wl4g/rust:1.93-slim

COPY foundry.tar.gz /tmp/foundry.tar.gz
RUN mkdir -p /opt/foundry \
    && tar -xzf /tmp/foundry.tar.gz -C /opt/foundry \
    && chmod +x /opt/foundry/* \
    && rm /tmp/foundry.tar.gz

ENV PATH="/opt/foundry:${PATH}"

EXPOSE 8545
ENTRYPOINT ["anvil"]
CMD ["--host", "0.0.0.0", "--port", "8545", "--accounts", "10", "--balance", "10000", "--chain-id", "31337"]
