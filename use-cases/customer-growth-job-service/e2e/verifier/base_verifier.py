"""Shared runtime clients and assertions for ordered E2E scenario verifiers."""

from __future__ import annotations

import base64
import json
import time
import traceback
from typing import Callable, Iterator, TypeVar
from urllib import error, request

from common.config import CONFIG_DIR
from common.kubernetes import (
    AUTHGUARD_API_TOKEN,
    KubernetesE2E,
)
from common.model import RunContext, VerificationResult
from common.telemetry import E2ETrace
from verifier.s20_observability_contract import JaegerQueryClient


T = TypeVar("T")


class BaseVerifier:
    """Compose Kubernetes infrastructure with fail-closed verifier utilities."""

    scenario_id = ""
    title = ""

    def __init__(self, context: RunContext) -> None:
        self.infrastructure = KubernetesE2E(context)
        self.context = context
        self.commands = self.infrastructure.commands
        self.details = self.infrastructure.details
        self._step_number = 0
        fixture = json.loads(
            (CONFIG_DIR / "authguard-e2e-scenarios.json").read_text(encoding="utf-8")
        )
        if fixture.get("version") != 4:
            raise ValueError("AuthGuard E2E fixture version must be 4")
        self.authn_scenarios = fixture["authn"]
        self.principal_scenarios = fixture["principal_federation"]
        self.authn_traces: dict[str, E2ETrace] = {}
        self.authn_trace_principals: dict[str, str] = {}
        self.api_trace_headers: dict[str, str] = {}

    def __getattr__(self, name: str):
        return getattr(self.infrastructure, name)

    def step(self, label: str, operation: Callable[[], T]) -> T:
        self._step_number += 1
        step = f"{self.scenario_id}.{self._step_number:02d}"
        started = time.monotonic()
        print(f"    [{step}] {label} ...", flush=True)
        try:
            result = operation()
        except Exception:
            print(f"    [{step}] FAIL ({time.monotonic() - started:.2f}s)", flush=True)
            raise
        print(f"    [{step}] PASS ({time.monotonic() - started:.2f}s)", flush=True)
        return result

    def execute(self, operation: Callable[[], None]) -> VerificationResult:
        started = time.monotonic()
        passed = False
        try:
            operation()
            passed = True
        except Exception:
            self.details.append(traceback.format_exc())
        return VerificationResult(
            scenario_id=self.scenario_id,
            title=self.title,
            passed=passed,
            duration_seconds=time.monotonic() - started,
            details=self.details,
            commands=self.commands,
        )

    def _verify_envoy_runtime_filter_chain(self) -> None:
        with self._forward_envoy_admin() as port:
            with request.urlopen(
                f"http://127.0.0.1:{port}/config_dump?resource=dynamic_listeners",
                timeout=15,
            ) as response:
                config_dump = json.loads(response.read())

        expected_ext_auth = (
            "envoy.filters.http.ext_authz/securitypolicy/"
            f"{self.namespace}/{self.authguard_release}"
        )
        for candidate in self._json_objects(config_dump):
            filters = candidate.get("http_filters")
            if not isinstance(filters, list):
                continue
            names = [item.get("name", "") for item in filters]
            if "envoy.filters.http.jwt_authn" not in names or expected_ext_auth not in names:
                continue
            jwt_index = names.index("envoy.filters.http.jwt_authn")
            ext_auth_index = names.index(expected_ext_auth)
            router_index = names.index("envoy.filters.http.router")
            if not jwt_index < ext_auth_index < router_index:
                raise RuntimeError(f"unsafe Envoy HTTP filter order: {names}")
            ext_auth = filters[ext_auth_index].get("typed_config", {})
            envoy_grpc = ext_auth.get("grpc_service", {}).get("envoy_grpc", {})
            expected_authority = f"{self.authguard_release}.{self.namespace}:8080"
            if envoy_grpc.get("authority") != expected_authority:
                raise RuntimeError(
                    "Envoy ext_authz runtime target mismatch: "
                    f"expected={expected_authority!r}, actual={envoy_grpc.get('authority')!r}"
                )
            self.details.append(
                "Envoy runtime filter order is jwt_authn -> ext_authz -> router; "
                f"ext_authz authority is {expected_authority}"
            )
            return
        raise RuntimeError("Envoy runtime config contains no JWT + Authguard ext_authz chain")

    @classmethod
    def _json_objects(cls, value: object) -> Iterator[dict]:
        if isinstance(value, dict):
            yield value
            for child in value.values():
                yield from cls._json_objects(child)
        elif isinstance(value, list):
            for child in value:
                yield from cls._json_objects(child)

    def _export_verifier_trace(self, trace: E2ETrace) -> None:
        with self._forward_service(self.jaeger_service, 4318) as collector_port:
            export_request = request.Request(
                f"http://127.0.0.1:{collector_port}/v1/traces",
                data=trace.otlp_json(),
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with request.urlopen(export_request, timeout=15) as response:
                if response.status not in {200, 202}:
                    raise RuntimeError(
                        f"Jaeger OTLP export returned HTTP {response.status}"
                    )

    def _jaeger_query(self, port: int) -> JaegerQueryClient:
        return JaegerQueryClient(
            base_url=f"http://127.0.0.1:{port}",
            timeout_seconds=min(self.context.timeout_seconds, 90),
        )

    @staticmethod
    def _jwt_claims(token: str) -> dict:
        parts = token.split(".")
        if len(parts) != 3:
            raise RuntimeError("identity issuer returned a malformed JWT")
        encoded = parts[1] + "=" * (-len(parts[1]) % 4)
        try:
            claims = json.loads(base64.urlsafe_b64decode(encoded))
        except (ValueError, json.JSONDecodeError) as failure:
            raise RuntimeError("identity issuer returned an invalid JWT payload") from failure
        if not isinstance(claims, dict):
            raise RuntimeError("identity JWT payload is not an object")
        return claims

    def _http(
        self,
        port: int,
        host: str,
        path: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        json_body: dict | None = None,
    ) -> tuple[int, str]:
        body = json.dumps(json_body).encode() if json_body is not None else None
        outgoing_headers = {"Host": host, **(headers or {})}
        if json_body is not None:
            outgoing_headers["Content-Type"] = "application/json"
        outgoing = request.Request(
            f"http://127.0.0.1:{port}{path}",
            data=body,
            method=method,
            headers=outgoing_headers,
        )
        try:
            with request.urlopen(outgoing, timeout=15) as response:
                return response.status, response.read().decode()
        except error.HTTPError as failure:
            return failure.code, failure.read().decode()

    def _api_http(
        self,
        port: int,
        path: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        json_body: dict | None = None,
    ) -> tuple[int, str]:
        return self._http(
            port,
            "authguard-management.local",
            path,
            method=method,
            headers={
                "Authorization": f"Bearer {AUTHGUARD_API_TOKEN}",
                **self.api_trace_headers,
                **(headers or {}),
            },
            json_body=json_body,
        )

    def _expect_status(self, scenario: str, actual: int, expected: int) -> None:
        if actual != expected:
            raise RuntimeError(f"{scenario}: expected HTTP {expected}, got {actual}")
        self.details.append(f"{scenario}: HTTP {actual}")

    def _expect_job_ids(self, scenario: str, body: str, expected: list[int]) -> None:
        actual = sorted(job["id"] for job in json.loads(body))
        if actual != sorted(expected):
            raise RuntimeError(f"{scenario}: expected job ids {expected}, got {actual}")
        self.details.append(f"{scenario}: job ids {actual}")

    def _postgresql_pod(self) -> str:
        return self._run(
            (
                "kubectl",
                "get",
                "pods",
                "-n",
                self.namespace,
                "-l",
                "app.kubernetes.io/component=e2e-authguard-postgresql",
                "-o",
                "jsonpath={.items[0].metadata.name}",
            )
        ).output.strip()

    def _postgresql_query(self, pod: str, sql: str) -> str:
        return self._run(
            (
                "kubectl",
                "exec",
                "-n",
                self.namespace,
                pod,
                "--",
                "bash",
                "-ec",
                'PGPASSWORD="$POSTGRESQL_POSTGRES_PASSWORD" psql '
                '-U postgres -d "$POSTGRESQL_DATABASE" -At '
                '--set=ON_ERROR_STOP=1 --command "$1"',
                "e2e-authguard-query",
                sql,
            )
        ).output.strip()
