FROM registry.cn-shenzhen.aliyuncs.com/wl4g/python:3.12-slim
WORKDIR /app
COPY use-cases/customer-growth-job-service/e2e/deploy/scim-sync-agent-service/requirements.txt /tmp/agent-requirements.txt
RUN pip install --no-cache-dir -r /tmp/agent-requirements.txt
COPY use-cases/customer-growth-job-service/e2e/deploy/scim-sync-agent-service /app/agent
RUN useradd --system --uid 65532 --no-create-home e2e-scim-agent
USER 65532:65532
ENTRYPOINT ["python", "/app/agent/sync_agent.py"]
