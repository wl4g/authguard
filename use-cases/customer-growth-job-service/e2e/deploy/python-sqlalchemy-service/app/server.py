from __future__ import annotations

from dataclasses import asdict
import logging
import os
import sys
from typing import Any, Callable

from flask import Flask, Response, jsonify, request
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from app.controller.customer_growth_job_controller import CustomerGrowthJobController
from app.dto.customer_growth_job_dto import (
    CustomerGrowthJobSearchRequest,
    CreateCustomerGrowthJobRequest,
    UpdateCustomerGrowthJobRequest,
)
from app.repository.customer_growth_job_repository import CustomerGrowthJobRepository
from app.service.customer_growth_job_service import CustomerGrowthJobService
from app.telemetry import instrument
from authguard_adapter.access import (
    AccessContextUnavailable,
    HeaderAccessContextResolver,
    GrpcAccessContextResolver,
)
from authguard_adapter.filter import AccessMiddleware
from authguard_adapter.util import configure_logger


CUSTOMER_GROWTH_SHELL = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Customer Growth</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; color: #e8f7f4; background: #070d16; }
    aside { position: fixed; inset: 0 auto 0 0; width: 240px; padding: 28px 20px;
      border-right: 1px solid #163342; background: #0a1520; }
    .brand { color: #51f1cf; font-size: 20px; font-weight: 750; letter-spacing: .03em; }
    .nav { margin-top: 40px; color: #9db8bd; }
    button { position: absolute; left: 20px; right: 20px; bottom: 24px; width: 200px;
      padding: 12px 16px; color: #d9efec; background: #10232e; border: 1px solid #285064;
      border-radius: 10px; cursor: pointer; text-align: left; }
    button:hover { border-color: #51f1cf; color: #51f1cf; }
    main { margin-left: 240px; padding: 64px; }
    h1 { margin: 0 0 12px; font-size: 34px; }
    p { color: #91aeb4; }
  </style>
</head>
<body>
  <aside>
    <div class="brand">Customer Growth</div>
    <div class="nav">Workflows</div>
    <button type="button" data-testid="business-sign-out">Sign out</button>
  </aside>
  <main>
    <h1>Customer Growth Workflows</h1>
    <p>Authenticated business application shell</p>
  </main>
  <script>
    document.querySelector('[data-testid="business-sign-out"]')
      .addEventListener('click', async () => {
        const response = await fetch('/auth/logout', {
          method: 'POST', credentials: 'same-origin'
        });
        if (!response.ok) throw new Error(`logout failed: ${response.status}`);
        window.location.assign('/auth/login?return_to=%2Fworkflows%2Flogout-proof');
      });
  </script>
</body>
</html>
"""


def create_app() -> Flask:
    app = Flask(__name__)
    instrument(app)
    adapter_logger = logging.getLogger("authguard.e2e.adapter")
    adapter_logger.handlers = [logging.StreamHandler(sys.stdout)]
    adapter_logger.setLevel(logging.DEBUG)
    adapter_logger.propagate = False
    configure_logger(adapter_logger)
    engine = _database_engine()

    @app.get("/healthz")
    def health() -> Response:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return Response("ok", status=200, mimetype="text/plain")

    @app.get("/workflows/logout-proof")
    def customer_growth_shell() -> Response:
        response = Response(CUSTOMER_GROWTH_SHELL, status=200, mimetype="text/html")
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/customer-growth/jobs")
    def list_jobs() -> Response:
        query = CustomerGrowthJobSearchRequest(
            workspace_id=request.args.get("workspace_id"),
            project_id=request.args.get("project_id"),
            status=request.args.get("status"),
            owner_user_id=request.args.get("owner_user_id"),
        )
        return _with_controller(engine, lambda controller: controller.list_visible_jobs(query))

    @app.get("/customer-growth/jobs/<int:job_id>")
    def get_job(job_id: int) -> Response:
        def operation(controller: CustomerGrowthJobController) -> Any:
            job = controller.get_job(job_id)
            if job is None:
                raise LookupError("customer growth job not found or not authorized")
            return job

        return _with_controller(engine, operation)

    @app.post("/customer-growth/jobs")
    def create_job() -> Response:
        payload = _json_payload()
        return _with_controller(
            engine,
            lambda controller: controller.create_job(CreateCustomerGrowthJobRequest(**payload)),
        )

    @app.put("/customer-growth/jobs/<int:job_id>")
    def update_job(job_id: int) -> Response:
        payload = _json_payload()
        return _with_controller(
            engine,
            lambda controller: controller.update_job(
                job_id, UpdateCustomerGrowthJobRequest(**payload)
            ),
        )

    @app.delete("/customer-growth/jobs/<int:job_id>")
    def delete_job(job_id: int) -> Response:
        _with_controller(engine, lambda controller: controller.delete_job(job_id))
        return Response(status=204)

    @app.errorhandler(LookupError)
    def not_found(error: LookupError) -> tuple[str, int]:
        return str(error), 404

    @app.errorhandler(AccessContextUnavailable)
    def unavailable(error: AccessContextUnavailable) -> tuple[str, int]:
        return str(error), 401

    @app.errorhandler(PermissionError)
    def forbidden(error: PermissionError) -> tuple[str, int]:
        return str(error), 403

    original_wsgi = app.wsgi_app
    resolvers = [HeaderAccessContextResolver.from_env()]
    if os.getenv("AUTHGUARD_GRPC_TARGET", "").strip():
        resolvers.append(GrpcAccessContextResolver.from_env())
    secured_wsgi = AccessMiddleware(original_wsgi, *resolvers)

    def authguard_wsgi(environ: dict[str, Any], start_response: Any) -> Any:
        if environ.get("PATH_INFO") in {"/healthz", "/workflows/logout-proof"}:
            return original_wsgi(environ, start_response)
        return secured_wsgi(environ, start_response)

    app.wsgi_app = authguard_wsgi
    return app


def _with_controller(
    engine: Engine, operation: Callable[[CustomerGrowthJobController], Any]
) -> Response:
    with engine.begin() as connection:
        controller = CustomerGrowthJobController(
            CustomerGrowthJobService(CustomerGrowthJobRepository(connection))
        )
        result = operation(controller)
        if result is None:
            return Response(status=204)
        if isinstance(result, list):
            return jsonify([asdict(item) for item in result])
        return jsonify(asdict(result))


def _database_engine() -> Engine:
    database_url = os.environ.get("DATABASE_URL", "").strip()
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")
    if database_url.startswith("postgresql://"):
        database_url = "postgresql+psycopg://" + database_url.removeprefix("postgresql://")
    return create_engine(database_url, pool_pre_ping=True, pool_size=5, max_overflow=5)


def _json_payload() -> dict[str, Any]:
    payload = request.get_json(silent=False)
    if not isinstance(payload, dict):
        raise ValueError("JSON object body is required")
    return payload


app = create_app()
