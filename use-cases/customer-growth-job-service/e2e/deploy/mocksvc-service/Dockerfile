FROM registry.cn-shenzhen.aliyuncs.com/wl4g/python:3.12-slim
WORKDIR /app
COPY use-cases/customer-growth-job-service/e2e/deploy/mocksvc-service/requirements.txt /tmp/service-requirements.txt
RUN pip install --no-cache-dir -r /tmp/service-requirements.txt
COPY use-cases/customer-growth-job-service/e2e/deploy/mocksvc-service /app/service
ENV PYTHONPATH=/app/service
RUN useradd --system --uid 65532 --no-create-home e2e-mocksvc
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["gunicorn", "--bind=0.0.0.0:8080", "--workers=2", "--threads=4", "--access-logfile=-", "app.server:app"]
