ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}
WORKDIR /app
COPY src/sdk/python/requirements.txt /tmp/authguard-sdk-requirements.txt
COPY use-cases/customer-growth-job-service/deploy/biz-python-sqlalchemy-service/source/requirements.txt /tmp/service-requirements.txt
ARG PIP_INDEX_URL=https://pypi.org/simple
RUN pip install --no-cache-dir -r /tmp/authguard-sdk-requirements.txt -r /tmp/service-requirements.txt
COPY src/sdk/python/sdk /app/sdk
COPY use-cases/customer-growth-job-service/deploy/biz-python-sqlalchemy-service/source /app/service
ENV PYTHONPATH=/app:/app/service
RUN useradd --system --uid 65532 --no-create-home e2e-authguard-python
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["gunicorn", "--bind=0.0.0.0:8080", "--workers=2", "--threads=4", "--access-logfile=-", "app.server:app"]
