FROM registry.cn-shenzhen.aliyuncs.com/wl4g/python:3.12-slim
WORKDIR /app
COPY use-cases/customer-growth-job-service/e2e/deploy/mocksvc-idp-service/requirements.txt /tmp/service-requirements.txt
RUN pip install --no-cache-dir -r /tmp/service-requirements.txt
COPY use-cases/customer-growth-job-service/e2e/deploy/mocksvc-idp-service /app/service
ENV PYTHONPATH=/app/service
RUN useradd --system --uid 65532 --no-create-home e2e-mock-idp
USER 65532:65532
EXPOSE 8080
# OAuth authorization codes are deliberately one-time in this disposable IdP;
# one worker keeps its in-memory fixture state coherent without adding a fake DB.
ENTRYPOINT ["gunicorn", "--bind=0.0.0.0:8080", "--workers=1", "--threads=4", "--access-logfile=-", "app.server:app"]
