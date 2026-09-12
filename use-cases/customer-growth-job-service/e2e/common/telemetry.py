"""Minimal dependency-free OpenTelemetry trace producer for the k3s verifier."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import secrets
import time


@dataclass
class E2ESpan:
    """One verifier-owned span exported through OTLP/HTTP JSON."""

    trace_id: str
    span_id: str
    parent_span_id: str | None
    name: str
    kind: int
    start_time_unix_nano: int
    attributes: dict[str, str] = field(default_factory=dict)
    end_time_unix_nano: int | None = None

    @property
    def traceparent(self) -> str:
        """Return a sampled W3C Trace Context header for downstream propagation."""
        return f"00-{self.trace_id}-{self.span_id}-01"

    def finish(self) -> None:
        """Close the span once; repeated calls preserve its original duration."""
        if self.end_time_unix_nano is None:
            self.end_time_unix_nano = time.time_ns()


class E2ETrace:
    """Models the verifier root and its explicit outbound client operations."""

    INTERNAL_SPAN = 1
    CLIENT_SPAN = 3

    def __init__(self, name: str, request_id: str | None = None) -> None:
        self.trace_id = secrets.token_hex(16)
        self.request_id = request_id or f"e2e-{secrets.token_hex(8)}"
        self.root = E2ESpan(
            trace_id=self.trace_id,
            span_id=secrets.token_hex(8),
            parent_span_id=None,
            name=name,
            kind=self.INTERNAL_SPAN,
            start_time_unix_nano=time.time_ns(),
            attributes={"e2e.request.id": self.request_id},
        )
        self.spans = [self.root]

    def start_client(self, name: str, **attributes: str) -> E2ESpan:
        """Start one client child beneath the verifier transaction root."""
        span = E2ESpan(
            trace_id=self.trace_id,
            span_id=secrets.token_hex(8),
            parent_span_id=self.root.span_id,
            name=name,
            kind=self.CLIENT_SPAN,
            start_time_unix_nano=time.time_ns(),
            attributes={"e2e.request.id": self.request_id, **attributes},
        )
        self.spans.append(span)
        return span

    def finish(self) -> None:
        """Close all unfinished children and then the transaction root."""
        for span in self.spans[1:]:
            span.finish()
        self.root.finish()

    def otlp_json(self) -> bytes:
        """Serialize verifier spans as an OTLP/HTTP JSON export request."""
        self.finish()
        spans = []
        for span in self.spans:
            spans.append(
                {
                    "traceId": span.trace_id,
                    "spanId": span.span_id,
                    **(
                        {"parentSpanId": span.parent_span_id}
                        if span.parent_span_id is not None
                        else {}
                    ),
                    "name": span.name,
                    "kind": span.kind,
                    "startTimeUnixNano": str(span.start_time_unix_nano),
                    "endTimeUnixNano": str(span.end_time_unix_nano),
                    "attributes": [
                        {"key": key, "value": {"stringValue": value}}
                        for key, value in sorted(span.attributes.items())
                    ],
                    "status": {"code": 1},
                }
            )
        payload = {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {
                                "key": "service.name",
                                "value": {"stringValue": "e2e-verifier"},
                            },
                            {
                                "key": "deployment.environment.name",
                                "value": {"stringValue": "e2e"},
                            },
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "authguard-e2e-verifier"},
                            "spans": spans,
                        }
                    ],
                }
            ]
        }
        return json.dumps(payload, separators=(",", ":")).encode()


@dataclass(frozen=True)
class JaegerTraceVerifier:
    """Validates the causal service graph returned by the Jaeger Query API."""

    keycloak_service: str
    envoy_service: str = "e2e-envoy-proxy"
    authguard_service: str = "authguard-authz"
    verifier_service: str = "e2e-verifier"

    def verify(self, payload: dict, trace: E2ETrace) -> None:
        """Require both client branches and the Envoy-to-Authguard Check edge."""
        traces = payload.get("data", [])
        if not traces:
            raise RuntimeError("Jaeger query returned no trace data")
        result = traces[0]
        processes = result.get("processes", {})
        spans = result.get("spans", [])
        services = {
            str(process["serviceName"])
            for process in processes.values()
            if isinstance(process, dict) and isinstance(process.get("serviceName"), str)
        }
        expected_services = {
            self.verifier_service,
            self.envoy_service,
            self.authguard_service,
            self.keycloak_service,
        }
        missing = expected_services - services
        if missing:
            raise RuntimeError(
                f"Jaeger trace is missing services {sorted(missing)}; "
                f"observed={sorted(services)}"
            )

        span_by_id = {span.get("spanID"): span for span in spans}
        authguard_spans = [
            span
            for span in spans
            if self._service_name(span, processes) == self.authguard_service
            and span.get("operationName") == "envoy.ext_authz.check"
        ]
        if len(authguard_spans) != 1:
            raise RuntimeError(
                "expected exactly one Authguard envoy.ext_authz.check span, "
                f"got {len(authguard_spans)}"
            )
        authguard = authguard_spans[0]
        tags = {tag.get("key"): tag.get("value") for tag in authguard.get("tags", [])}
        expected_tags = {
            "rpc.service": "envoy.service.auth.v3.Authorization",
            "rpc.method": "Check",
            "authguard.decision": "allow",
        }
        mismatches = {
            key: (expected, tags.get(key))
            for key, expected in expected_tags.items()
            if tags.get(key) != expected
        }
        if mismatches:
            raise RuntimeError(f"Authguard trace tag mismatch: {mismatches}")

        envoy_ingress_spans = [
            span
            for span in spans
            if self._service_name(span, processes) == self.envoy_service
            and span.get("operationName") == "ingress"
        ]
        if len(envoy_ingress_spans) != 1:
            raise RuntimeError(
                "expected exactly one Envoy ingress span, "
                f"got {len(envoy_ingress_spans)}"
            )
        envoy_tags = {
            tag.get("key"): tag.get("value")
            for tag in envoy_ingress_spans[0].get("tags", [])
        }
        envoy_request_id = envoy_tags.get("guid:x-request-id")
        if not isinstance(envoy_request_id, str) or not envoy_request_id:
            raise RuntimeError("Envoy ingress span is missing guid:x-request-id")
        if tags.get("http.request.id") != envoy_request_id:
            raise RuntimeError(
                "request ID propagation mismatch between Envoy and Authguard: "
                f"envoy={envoy_request_id!r}, "
                f"authguard={tags.get('http.request.id')!r}"
            )

        envoy_span_ids = {
            span.get("spanID")
            for span in spans
            if self._service_name(span, processes) == self.envoy_service
        }
        if not self._has_ancestor(authguard, envoy_span_ids, span_by_id):
            raise RuntimeError("Authguard Check span is not a descendant of Envoy Proxy")

        client_span_ids = {span.name: span.span_id for span in trace.spans}
        branches = {
            self.keycloak_service: client_span_ids["keycloak.token"],
            self.envoy_service: client_span_ids["envoy.customer_growth_jobs"],
        }
        for service, client_span_id in branches.items():
            downstream = [
                span
                for span in spans
                if self._service_name(span, processes) == service
            ]
            if not any(
                self._has_ancestor(span, {client_span_id}, span_by_id)
                for span in downstream
            ):
                raise RuntimeError(
                    f"{service} span is not linked to its verifier client branch"
                )

    @staticmethod
    def _service_name(span: dict, processes: dict) -> str | None:
        process = processes.get(span.get("processID"), {})
        return process.get("serviceName") if isinstance(process, dict) else None

    @staticmethod
    def _has_ancestor(
        span: dict,
        ancestor_ids: set[str | None],
        span_by_id: dict[str | None, dict],
    ) -> bool:
        visited: set[str] = set()
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
