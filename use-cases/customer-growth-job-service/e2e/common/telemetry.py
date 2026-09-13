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
        self.request_id = request_id or f"e2e-authguard-{secrets.token_hex(8)}"
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
                                "value": {"stringValue": "e2e-authguard-verifier"},
                            },
                            {
                                "key": "deployment.environment.name",
                                "value": {"stringValue": "e2e"},
                            },
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "e2e-authguard-verifier"},
                            "spans": spans,
                        }
                    ],
                }
            ]
        }
        return json.dumps(payload, separators=(",", ":")).encode()
