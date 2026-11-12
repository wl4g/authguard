ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}
WORKDIR /app
COPY use-cases/customer-growth-job-service/deploy/mock-external-idp-service/source/requirements.txt /tmp/service-requirements.txt
ARG PIP_INDEX_URL=https://pypi.org/simple
RUN pip install --no-cache-dir -r /tmp/service-requirements.txt
COPY use-cases/customer-growth-job-service/deploy/mock-external-idp-service/source /app/service
ENV PYTHONPATH=/app/service
RUN useradd --system --uid 65532 --no-create-home e2e-authguard-mock-idp
USER 65532:65532
EXPOSE 8080
# OAuth authorization codes are deliberately one-time in this disposable IdP;
# one worker keeps its in-memory scenario_data state coherent without adding a fake DB.
ENTRYPOINT ["gunicorn", "--bind=0.0.0.0:8080", "--workers=1", "--threads=4", "--access-logfile=-", "app.server:app"]
