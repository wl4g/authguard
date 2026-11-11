ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}
WORKDIR /app
COPY src/adapters/python/requirements.txt /tmp/authguard-sdk-requirements.txt
COPY use-cases/customer-growth-job-service/deploy/biz-python-sqlalchemy-service/source/requirements.txt /tmp/service-requirements.txt
RUN pip install --no-cache-dir -r /tmp/authguard-sdk-requirements.txt -r /tmp/service-requirements.txt
COPY src/adapters/python /app/sdk
COPY use-cases/customer-growth-job-service/deploy/biz-python-sqlalchemy-service/source /app/service
ENV PYTHONPATH=/app/sdk:/app/service
RUN useradd --system --uid 65532 --no-create-home e2e-authguard-python
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["gunicorn", "--bind=0.0.0.0:8080", "--workers=2", "--threads=4", "--access-logfile=-", "app.server:app"]
