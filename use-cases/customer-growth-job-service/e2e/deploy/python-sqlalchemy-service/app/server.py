from __future__ import annotations

from dataclasses import asdict
import os
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
from authguard_adapter.access import (
    AccessContextUnavailable,
    HeaderAccessContextResolver,
    GrpcAccessContextResolver,
)
from authguard_adapter.filter import AccessMiddleware


def create_app() -> Flask:
    app = Flask(__name__)
    engine = _database_engine()

    @app.get("/healthz")
    def health() -> Response:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return Response("ok", status=200, mimetype="text/plain")

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
        if environ.get("PATH_INFO") == "/healthz":
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
