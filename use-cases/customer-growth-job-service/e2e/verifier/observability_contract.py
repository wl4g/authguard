"""Fail-closed observability contracts for the deployed AuthGuard product."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from common.telemetry import E2ETrace


AUTHN_LOG_EVENTS = frozenset(
    {
        "authguard.authn.authorize.started",
        "authguard.authn.authorize.succeeded",
        "authguard.authn.callback.started",
        "authguard.authn.provider.started",
        "authguard.authn.provider.succeeded",
        "authguard.authn.account_linking.started",
        "authguard.authn.account_linking.succeeded",
        "authguard.authn.callback.succeeded",
    }
)

AUTHZ_LOG_EVENTS = frozenset(
    {
        "authguard.authz.ext_authz.started",
        "authguard.authz.ext_authz.completed",
        "authguard.authz.scope_resolution.started",
        "authguard.authz.scope_resolution.succeeded",
        "authguard.authz.principal_discovery.started",
        "authguard.authz.principal_discovery.succeeded",
        "authguard.authz.principal_materialization.started",
        "authguard.authz.principal_materialization.succeeded",
    }
)

ADAPTER_LOG_EVENTS = frozenset(
    {
        "authguard.access_filter.started",
        "authguard.access_context.header.started",
        "authguard.access_context.header.succeeded",
        "authguard.access_context.grpc.started",
        "authguard.access_context.grpc.succeeded",
        "authguard.sql_scope.compile.started",
        "authguard.sql_scope.compile.succeeded",
    }
)


def require_json_events(logs: str, required: frozenset[str], component: str) -> int:
    """Require service events to be actual JSON fields, not accidental text matches."""
    observed: set[str] = set()
    json_records = 0
    for line in logs.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        json_records += 1
        fields = record.get("fields", {})
        event = fields.get("event") if isinstance(fields, dict) else None
        if isinstance(event, str):
            observed.add(event)
    missing = required - observed
    if missing:
        raise RuntimeError(
            f"{component} structured-log contract is missing events {sorted(missing)}; "
            f"observed={sorted(observed)}"
        )
    return json_records


def require_adapter_events(logs: str, component: str) -> None:
    """Require both resolver modes and SQL translation in each SDK workload log."""
    observed = set(re.findall(r"authguard\.[a-z0-9_.]+", logs))
    missing = ADAPTER_LOG_EVENTS - observed
    if missing:
        raise RuntimeError(
            f"{component} adapter-log contract is missing events {sorted(missing)}; "
            f"observed={sorted(observed)}"
        )


def require_metric(
    metrics: str,
    name: str,
    labels: dict[str, str] | None = None,
) -> float:
    """Return a positive OpenMetrics sample matching an order-independent label subset."""
    expected = labels or {}
    for line in metrics.splitlines():
        if not line.startswith(name):
            continue
        match = re.fullmatch(
            rf"{re.escape(name)}(?:\{{(?P<labels>[^}}]*)\}})?\s+(?P<value>[-+0-9.eE]+)",
            line,
        )
        if match is None:
            continue
        parsed = {
            key: value
            for key, value in re.findall(r'(\w+)="([^"]*)"', match.group("labels") or "")
        }
        if all(parsed.get(key) == value for key, value in expected.items()):
            sample = float(match.group("value"))
            if sample > 0:
                return sample
    raise RuntimeError(
        f"positive metric sample is missing: {name} labels={dict(sorted(expected.items()))}"
    )


def verify_authn_metrics(metrics: str, providers: tuple[str, ...]) -> None:
    for provider in providers:
        for operation in ("authorize", "callback"):
            require_metric(
                metrics,
                "authguard_authn_flows_total",
                {
                    "provider": provider,
                    "operation": operation,
                    "outcome": "success",
                },
            )
    require_metric(metrics, "authguard_authn_flow_duration_seconds_count")


def verify_authz_metrics(metrics: str) -> None:
    for decision in ("allow", "deny"):
        require_metric(
            metrics,
            "authguard_authorization_decisions_total",
            {"decision": decision},
        )
    for mode in ("direct", "token"):
        require_metric(metrics, "authguard_scope_deliveries_total", {"mode": mode})
    require_metric(metrics, "authguard_scope_resolutions_total", {"outcome": "hit"})
    require_metric(metrics, "authguard_authorization_duration_seconds_count")
    require_metric(metrics, "authguard_scope_resolution_duration_seconds_count")


@dataclass(frozen=True)
class AuthnJaegerTraceVerifier:
    """Proves AuthN inbound tracing and provider child-span export through Jaeger API."""

    provider: str
    envoy_service: str = "e2e-envoy-proxy"
    authn_service: str = "authguard-authn"
    verifier_service: str = "e2e-verifier"

    def verify(self, payload: dict, trace: E2ETrace) -> None:
        traces = payload.get("data", [])
        if not traces:
            raise RuntimeError("Jaeger query returned no AuthN trace data")
        result = traces[0]
        processes = result.get("processes", {})
        spans = result.get("spans", [])
        services = {
            process.get("serviceName")
            for process in processes.values()
            if isinstance(process, dict)
        }
        expected = {self.verifier_service, self.envoy_service, self.authn_service}
        if missing := expected - services:
            raise RuntimeError(
                f"AuthN Jaeger trace is missing services {sorted(missing)}; "
                f"observed={sorted(service for service in services if service)}"
            )

        span_by_id = {span.get("spanID"): span for span in spans}
        authn_http_spans = [
            span
            for span in spans
            if self._service_name(span, processes) == self.authn_service
            and span.get("operationName") == "http.server.request"
        ]
        paths = {
            self._tags(span).get("url.path"): span for span in authn_http_spans
        }
        expected_paths = {
            f"/auth/v1/providers/{self.provider}/authorize",
            f"/auth/v1/providers/{self.provider}/callback",
        }
        if missing := expected_paths - paths.keys():
            raise RuntimeError(f"AuthN Jaeger trace is missing HTTP spans for {sorted(missing)}")

        provider_spans = [
            span
            for span in spans
            if self._service_name(span, processes) == self.authn_service
            and span.get("operationName") == "authn.provider.authenticate"
            and self._tags(span).get("authguard.provider") == self.provider
        ]
        if len(provider_spans) != 1:
            raise RuntimeError(
                f"expected one AuthN provider span for {self.provider}, got {len(provider_spans)}"
            )
        callback_span = paths[f"/auth/v1/providers/{self.provider}/callback"]
        if not self._has_ancestor(provider_spans[0], {callback_span.get("spanID")}, span_by_id):
            raise RuntimeError("AuthN provider span is not a child of its callback server span")

        envoy_span_ids = {
            span.get("spanID")
            for span in spans
            if self._service_name(span, processes) == self.envoy_service
        }
        for path in expected_paths:
            if not self._has_ancestor(paths[path], envoy_span_ids, span_by_id):
                raise RuntimeError(f"AuthN {path} span is not downstream of Envoy")

    @staticmethod
    def _service_name(span: dict, processes: dict) -> str | None:
        process = processes.get(span.get("processID"), {})
        return process.get("serviceName") if isinstance(process, dict) else None

    @staticmethod
    def _tags(span: dict) -> dict[str, object]:
        return {tag.get("key"): tag.get("value") for tag in span.get("tags", [])}

    @staticmethod
    def _has_ancestor(
        span: dict,
        ancestor_ids: set[object],
        span_by_id: dict[object, dict],
    ) -> bool:
        visited: set[object] = set()
        current = span
        while True:
            parent_id = next(
                (
                    reference.get("spanID")
                    for reference in current.get("references", [])
                    if reference.get("refType") == "CHILD_OF"
                ),
                None,
            )
            if parent_id is None or parent_id in visited:
                return False
            if parent_id in ancestor_ids:
                return True
            visited.add(parent_id)
            parent = span_by_id.get(parent_id)
            if parent is None:
                return False
            current = parent


@dataclass(frozen=True)
class ControlPlaneJaegerTraceVerifier:
    """Proves that administrator federation and policy calls reached AuthZ."""

    authz_service: str = "authguard-authz"
    verifier_service: str = "e2e-verifier"

    def verify(self, payload: dict, trace: E2ETrace) -> None:
        traces = payload.get("data", [])
        if not traces:
            raise RuntimeError("Jaeger query returned no administrator trace data")
        result = traces[0]
        processes = result.get("processes", {})
        spans = result.get("spans", [])
        services = {
            process.get("serviceName")
            for process in processes.values()
            if isinstance(process, dict)
        }
        if missing := {self.verifier_service, self.authz_service} - services:
            raise RuntimeError(
                f"administrator trace is missing services {sorted(missing)}"
            )

        authz_spans = [
            span
            for span in spans
            if AuthnJaegerTraceVerifier._service_name(span, processes)
            == self.authz_service
            and span.get("operationName") == "http.server.request"
        ]
        paths = {
            AuthnJaegerTraceVerifier._tags(span).get("url.path")
            for span in authz_spans
        }
        required = {
            "/api/v1/principal-discovery/search",
            "/api/v1/principal-discovery/materialize",
            "/api/v1/policy",
        }
        if missing := required - paths:
            raise RuntimeError(
                f"administrator trace is missing AuthZ paths {sorted(missing)}"
            )

        client_ids = {
            span.span_id
            for span in trace.spans
            if span.name == "authz.administrator.preauthorization"
        }
        span_by_id = {span.get("spanID"): span for span in spans}
        if len(client_ids) != 1 or not all(
            AuthnJaegerTraceVerifier._has_ancestor(span, client_ids, span_by_id)
            for span in authz_spans
        ):
            raise RuntimeError(
                "AuthZ control-plane spans are not descendants of the administrator client span"
            )
