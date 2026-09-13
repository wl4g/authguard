"""Phase 20 fail-closed observability contracts for the deployed AuthGuard product."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Protocol
from urllib import error, parse, request

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
        "authguard.authn.token_exchange.started",
        "authguard.authn.token_exchange.succeeded",
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
        "authguard.authz.scim_provisioning.started",
        "authguard.authz.scim_provisioning.succeeded",
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


class JaegerVerifier(Protocol):
    def verify(self, payload: dict, trace: E2ETrace) -> None: ...


@dataclass(frozen=True)
class JaegerQueryClient:
    """Query persisted Jaeger data and fail unless a complete trace is observable."""

    base_url: str
    timeout_seconds: int = 90

    def wait_for_trace(self, trace: E2ETrace, verifier: JaegerVerifier) -> dict:
        deadline = time.monotonic() + self.timeout_seconds
        last_failure = "trace was not returned"
        while time.monotonic() < deadline:
            try:
                payload = self._get(f"/api/traces/{trace.trace_id}")
                verifier.verify(payload, trace)
                return payload
            except (error.HTTPError, error.URLError, RuntimeError, ValueError) as failure:
                last_failure = str(failure)
                time.sleep(1)
        raise RuntimeError(
            f"Jaeger trace {trace.trace_id} did not become complete: {last_failure}"
        )

    def require_services(self, expected: set[str]) -> set[str]:
        deadline = time.monotonic() + min(self.timeout_seconds, 60)
        observed: set[str] = set()
        while time.monotonic() < deadline:
            try:
                payload = self._get("/api/services")
                observed = {
                    service
                    for service in payload.get("data", [])
                    if isinstance(service, str)
                }
                if expected <= observed:
                    return observed
            except (error.HTTPError, error.URLError, ValueError):
                pass
            time.sleep(1)
        raise RuntimeError(
            f"Jaeger /api/services is missing {sorted(expected - observed)}; "
            f"observed={sorted(observed)}"
        )

    def require_recent_traces(self, services: set[str]) -> None:
        missing = []
        for service in sorted(services):
            query = parse.urlencode({"service": service, "limit": 20, "lookback": "1h"})
            traces = self._get(f"/api/traces?{query}").get("data", [])
            if not any(trace.get("spans") for trace in traces):
                missing.append(service)
        if missing:
            raise RuntimeError(f"Jaeger has no recent traces for {missing}")

    def _get(self, path: str) -> dict:
        with request.urlopen(f"{self.base_url}{path}", timeout=15) as response:
            return json.loads(response.read())


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
            rf"{re.escape(name)}(?:\{{(?P<labels>.*)\}})?\s+(?P<value>[-+0-9.eE]+)",
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


def verify_authn_metrics(
    metrics: str,
    providers: tuple[str, ...],
    token_exchange_providers: tuple[str, ...] = (),
) -> None:
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
    for provider in token_exchange_providers:
        require_metric(
            metrics,
            "authguard_authn_flows_total",
            {
                "provider": provider,
                "operation": "token_exchange",
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
    require_metric(
        metrics,
        "authguard_http_requests_total",
        {"route": "/scim/v2/Users/{id}", "method": "PUT", "status": "200"},
    )


@dataclass(frozen=True)
class JaegerTrace:
    """Small graph view over one Jaeger Query API trace response."""

    spans: tuple[dict, ...]
    processes: dict

    @classmethod
    def parse(cls, payload: dict) -> "JaegerTrace":
        traces = payload.get("data", [])
        if len(traces) != 1:
            raise RuntimeError(f"expected one Jaeger trace, got {len(traces)}")
        return cls(tuple(traces[0].get("spans", [])), traces[0].get("processes", {}))

    @property
    def services(self) -> set[str]:
        return {
            process["serviceName"]
            for process in self.processes.values()
            if isinstance(process, dict) and isinstance(process.get("serviceName"), str)
        }

    def require_services(self, expected: set[str]) -> None:
        if missing := expected - self.services:
            raise RuntimeError(
                f"Jaeger trace is missing services {sorted(missing)}; "
                f"observed={sorted(self.services)}"
            )

    def select(self, service: str, operation: str | None = None) -> list[dict]:
        return [
            span
            for span in self.spans
            if self.service(span) == service
            and (operation is None or span.get("operationName") == operation)
        ]

    def service(self, span: dict) -> str | None:
        process = self.processes.get(span.get("processID"), {})
        return process.get("serviceName") if isinstance(process, dict) else None

    @staticmethod
    def tags(span: dict) -> dict[str, object]:
        return {tag.get("key"): tag.get("value") for tag in span.get("tags", [])}

    @staticmethod
    def event(span: dict, name: str) -> dict[str, object] | None:
        for log in span.get("logs", []):
            fields = {field.get("key"): field.get("value") for field in log.get("fields", [])}
            if fields.get("event") == name:
                return fields
        return None

    def descends_from(self, span: dict, ancestors: set[object]) -> bool:
        by_id = {item.get("spanID"): item for item in self.spans}
        visited: set[object] = set()
        while True:
            parent = next(
                (
                    reference.get("spanID")
                    for reference in span.get("references", [])
                    if reference.get("refType") == "CHILD_OF"
                ),
                None,
            )
            if parent is None or parent in visited:
                return False
            if parent in ancestors:
                return True
            visited.add(parent)
            span = by_id.get(parent, {})

    def downstream(self, spans: list[dict], ancestors: set[object]) -> list[dict]:
        return [span for span in spans if self.descends_from(span, ancestors)]


@dataclass(frozen=True)
class AuthnJaegerTraceVerifier:
    """Proves browser -> Envoy -> AuthN -> provider -> canonical Principal."""

    provider: str
    principal_id: str
    envoy_service: str = "e2e-authguard-envoy-proxy"
    authn_service: str = "authguard-authn"
    verifier_service: str = "e2e-authguard-verifier"

    def verify(self, payload: dict, trace: E2ETrace) -> None:
        graph = JaegerTrace.parse(payload)
        graph.require_services({self.verifier_service, self.envoy_service, self.authn_service})
        authn_spans = graph.select(self.authn_service, "http.server.request")
        paths = {graph.tags(span).get("url.path"): span for span in authn_spans}
        route_by_client = {
            "envoy.authn.authorize": f"/auth/v1/providers/{self.provider}/authorize",
            "envoy.authn.callback": f"/auth/v1/providers/{self.provider}/callback",
        }
        client_ids = {span.name: span.span_id for span in trace.spans}
        envoy_spans = graph.select(self.envoy_service)
        for client_name, path in route_by_client.items():
            authn_span = paths.get(path)
            if authn_span is None:
                raise RuntimeError(f"AuthN Jaeger trace is missing {path}")
            branch = graph.downstream(envoy_spans, {client_ids[client_name]})
            if not branch or not graph.descends_from(
                authn_span, {span.get("spanID") for span in branch}
            ):
                raise RuntimeError(f"AuthN {path} is not on its verifier -> Envoy branch")

        callback = paths[route_by_client["envoy.authn.callback"]]
        providers = [
            span
            for span in graph.select(self.authn_service, "authn.provider.authenticate")
            if graph.tags(span).get("authguard.provider") == self.provider
            and graph.descends_from(span, {callback.get("spanID")})
        ]
        if len(providers) != 1:
            raise RuntimeError(
                f"expected one callback provider span for {self.provider}, got {len(providers)}"
            )
        linked = graph.event(callback, "authguard.authn.account_linking.succeeded")
        if linked is None or linked.get("principal_id") != self.principal_id:
            raise RuntimeError(
                "AuthN trace lacks canonical account-linking evidence for "
                f"principal {self.principal_id!r}"
            )


@dataclass(frozen=True)
class OidcJaegerTraceVerifier:
    """Proves client -> Envoy -> AuthN OIDC normalization -> canonical Principal."""

    principal_id: str
    provider: str = "e2e-authguard-keycloak"
    envoy_service: str = "e2e-authguard-envoy-proxy"
    authn_service: str = "authguard-authn"
    verifier_service: str = "e2e-authguard-verifier"

    def verify(self, payload: dict, trace: E2ETrace) -> None:
        graph = JaegerTrace.parse(payload)
        graph.require_services({self.verifier_service, self.envoy_service, self.authn_service})
        client = next(span.span_id for span in trace.spans if span.name == "envoy.authn.oidc")
        envoy = graph.downstream(graph.select(self.envoy_service), {client})
        route = f"/auth/v1/providers/{self.provider}/token-exchange"
        authn = [
            span
            for span in graph.select(self.authn_service, "http.server.request")
            if graph.tags(span).get("url.path") == route
            and graph.descends_from(span, {item.get("spanID") for item in envoy})
        ]
        if len(authn) != 1:
            raise RuntimeError("OIDC token exchange is not on its verifier -> Envoy -> AuthN branch")
        providers = [
            span
            for span in graph.select(self.authn_service, "authn.provider.authenticate")
            if graph.tags(span).get("authguard.provider") == self.provider
            and graph.tags(span).get("authguard.provider.flow") == "token_exchange"
            and graph.descends_from(span, {authn[0].get("spanID")})
        ]
        linked = graph.event(authn[0], "authguard.authn.account_linking.succeeded")
        if len(providers) != 1 or linked is None or linked.get("principal_id") != self.principal_id:
            raise RuntimeError("OIDC trace lacks provider normalization or canonical linking evidence")


@dataclass(frozen=True)
class AuthorizationJaegerTraceVerifier:
    """Proves client -> Envoy -> AuthZ and Envoy -> Biz in one request trace."""

    workload_service: str
    envoy_service: str = "e2e-authguard-envoy-proxy"
    authz_service: str = "authguard-authz"
    verifier_service: str = "e2e-authguard-verifier"

    def verify(self, payload: dict, trace: E2ETrace) -> None:
        graph = JaegerTrace.parse(payload)
        graph.require_services(
            {self.verifier_service, self.envoy_service, self.authz_service, self.workload_service}
        )
        client = next(
            (span.span_id for span in trace.spans if span.name == "envoy.customer_growth_jobs"),
            None,
        )
        ingress = graph.downstream(graph.select(self.envoy_service, "ingress"), {client})
        if len(ingress) != 1:
            raise RuntimeError(f"expected one Envoy ingress on verifier branch, got {len(ingress)}")
        ingress_id = {ingress[0].get("spanID")}
        authz = graph.downstream(
            graph.select(self.authz_service, "envoy.ext_authz.check"), ingress_id
        )
        workloads = graph.downstream(graph.select(self.workload_service), ingress_id)
        if len(authz) != 1:
            raise RuntimeError(f"expected one AuthZ Check below Envoy, got {len(authz)}")
        if not workloads:
            raise RuntimeError(f"{self.workload_service} exported no span below Envoy")
        authz_tags = graph.tags(authz[0])
        expected = {
            "rpc.service": "envoy.service.auth.v3.Authorization",
            "rpc.method": "Check",
            "authguard.decision": "allow",
        }
        if mismatch := {
            key: (value, authz_tags.get(key))
            for key, value in expected.items()
            if authz_tags.get(key) != value
        }:
            raise RuntimeError(f"AuthZ trace tag mismatch: {mismatch}")
        request_id = graph.tags(ingress[0]).get("guid:x-request-id")
        if not request_id or authz_tags.get("http.request.id") != request_id:
            raise RuntimeError("x-request-id was not preserved from Envoy to AuthZ")


@dataclass(frozen=True)
class ControlPlaneJaegerTraceVerifier:
    """Proves that administrator federation and policy calls reached AuthZ."""

    authz_service: str = "authguard-authz"
    verifier_service: str = "e2e-authguard-verifier"

    def verify(self, payload: dict, trace: E2ETrace) -> None:
        graph = JaegerTrace.parse(payload)
        graph.require_services({self.verifier_service, self.authz_service})
        authz_spans = graph.select(self.authz_service, "http.server.request")
        paths = {graph.tags(span).get("url.path") for span in authz_spans}
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
        if len(client_ids) != 1 or not all(
            graph.descends_from(span, client_ids)
            for span in authz_spans
        ):
            raise RuntimeError(
                "AuthZ control-plane spans are not descendants of the administrator client span"
            )
