from __future__ import annotations
from urllib import error, request
from util.constant import E2EOtherDefinitions
import json
import re
from verifier.context import BaseVerifier, VerificationContext, VerificationResult


class E2ES40MetricsVerifier(BaseVerifier):
    scenario_id = "40"
    title = "Observability: metrics and management diagnostics"

    def deploy(self, context: VerificationContext) -> None:
        """Reuse the deployment owned by scenario 00."""

    def init(self, context: VerificationContext) -> None:
        """No additional input initialization is required."""

    def verifier(self, context: VerificationContext) -> VerificationResult:
        return self.execute(self._verify)

    def _verify(self) -> None:
        self.step(
            "query AuthN/AuthZ Prometheus metrics and process profiles",
            self._verify_metrics,
        )
        self.step(
            "verify exact metric increments for controlled AuthN/AuthZ requests",
            self._verify_counter_deltas,
        )

    def _verify_metrics(self) -> None:
        management = E2EOtherDefinitions.management()
        with self._forward_service(
            self.authguard_authz_service, int(management["port"])
        ) as port:
            with request.urlopen(
                f"http://127.0.0.1:{port}{management['metrics']['path']}", timeout=15
            ) as response:
                metrics = response.read().decode()
            self._verify_management_diagnostics(port, metrics, "authguard-authz")
        E2ES40MetricsVerifier.verify_authz_metrics(metrics)
        with self._forward_service(
            self.authguard_authn_service, int(management["port"])
        ) as port:
            with request.urlopen(
                f"http://127.0.0.1:{port}{management['metrics']['path']}", timeout=15
            ) as response:
                authn_metrics = response.read().decode()
            self._verify_management_diagnostics(port, authn_metrics, "authguard-authn")
        providers = tuple(
            (flow["provider_id"] for flow in self.authn_scenarios["provider_flows"])
        )
        E2ES40MetricsVerifier.verify_authn_metrics(
            authn_metrics, providers, ("e2e-authguard-keycloak",)
        )
        self.details.append(
            "Positive OpenMetrics samples verified independently from AuthN :9091 and AuthZ :9091: authorize/callback latency, allow/deny decisions, and direct/opaque scope delivery/resolution"
        )
        self.verify_metric_accounting(metrics, authn_metrics)

    def _verify_management_diagnostics(
        self, port: int, configured_metrics: str, component: str
    ) -> None:
        with request.urlopen(
            f"http://127.0.0.1:{port}/_/metrics", timeout=15
        ) as response:
            canonical_metrics = response.read().decode()
        if (
            "# HELP authguard_" not in canonical_metrics
            or "# HELP authguard_" not in configured_metrics
        ):
            raise RuntimeError(
                f"{component}: management metric endpoints returned no registry"
            )
        with request.urlopen(
            f"http://127.0.0.1:{port}/_/pprof", timeout=15
        ) as response:
            profile = json.loads(response.read().decode())
        required = {
            "pid",
            "logicalCpus",
            "userCpuTicks",
            "systemCpuTicks",
            "residentMemoryKib",
            "virtualMemoryKib",
            "threads",
        }
        missing = required - profile.keys()
        if missing or not all((profile.get(name) is not None for name in required)):
            raise RuntimeError(
                f"{component}: /_/pprof is missing runtime fields {sorted(missing)}"
            )
        self.details.append(
            f"{component} common management routes expose /_/metrics and bounded CPU/memory runtime diagnostics at /_/pprof"
        )

    @staticmethod
    def require_metric(
        metrics: str, name: str, labels: dict[str, str] | None = None
    ) -> float:
        """Return a positive OpenMetrics sample matching an order-independent label subset."""
        expected = labels or {}
        for line in metrics.splitlines():
            if not line.startswith(name):
                continue
            match = re.fullmatch(
                f"{re.escape(name)}(?:\\{{(?P<labels>.*)\\}})?\\s+(?P<value>[-+0-9.eE]+)",
                line,
            )
            if match is None:
                continue
            parsed = {
                key: value
                for key, value in re.findall(
                    '(\\w+)="([^"]*)"', match.group("labels") or ""
                )
            }
            if all((parsed.get(key) == value for key, value in expected.items())):
                sample = float(match.group("value"))
                if sample > 0:
                    return sample
        raise RuntimeError(
            f"positive metric sample is missing: {name} labels={dict(sorted(expected.items()))}"
        )

    @staticmethod
    def verify_authn_metrics(
        metrics: str,
        providers: tuple[str, ...],
        token_exchange_providers: tuple[str, ...] = (),
    ) -> None:
        for provider in providers:
            for operation in ("authorize", "callback"):
                E2ES40MetricsVerifier.require_metric(
                    metrics,
                    "authguard_authn_flows_total",
                    {
                        "provider": provider,
                        "operation": operation,
                        "outcome": "success",
                    },
                )
        for provider in token_exchange_providers:
            E2ES40MetricsVerifier.require_metric(
                metrics,
                "authguard_authn_flows_total",
                {
                    "provider": provider,
                    "operation": "token_exchange",
                    "outcome": "success",
                },
            )
        E2ES40MetricsVerifier.require_metric(
            metrics, "authguard_authn_flow_duration_seconds_count"
        )

    @staticmethod
    def verify_authz_metrics(metrics: str) -> None:
        for decision in ("allow", "deny"):
            E2ES40MetricsVerifier.require_metric(
                metrics,
                "authguard_authorization_decisions_total",
                {"decision": decision},
            )
        for mode in ("direct", "token"):
            E2ES40MetricsVerifier.require_metric(
                metrics, "authguard_scope_deliveries_total", {"mode": mode}
            )
        E2ES40MetricsVerifier.require_metric(
            metrics, "authguard_scope_resolutions_total", {"outcome": "hit"}
        )
        E2ES40MetricsVerifier.require_metric(
            metrics, "authguard_authorization_duration_seconds_count"
        )
        E2ES40MetricsVerifier.require_metric(
            metrics, "authguard_scope_resolution_duration_seconds_count"
        )
        E2ES40MetricsVerifier.require_metric(
            metrics,
            "authguard_http_requests_total",
            {"route": "/scim/v2/Users/{id}", "method": "PUT", "status": "200"},
        )

    @staticmethod
    def metric_sum(
        metrics: str, name: str, labels: dict[str, str] | None = None
    ) -> float:
        total = 0.0
        for line in metrics.splitlines():
            match = re.fullmatch(
                re.escape(name) + "(?:\\{(.*)\\})?\\s+([-+0-9.eE]+)", line
            )
            if match is None:
                continue
            parsed = dict(re.findall('(\\w+)="([^"]*)"', match.group(1) or ""))
            if all((parsed.get(key) == value for key, value in (labels or {}).items())):
                total += float(match.group(2))
        return total

    @classmethod
    def verify_metric_accounting(cls, authz: str, authn: str) -> None:
        pairs = [
            (
                authn,
                "authguard_authn_flow_duration_seconds_count",
                "authguard_authn_flows_total",
            ),
            (
                authz,
                "authguard_authorization_duration_seconds_count",
                "authguard_authorization_decisions_total",
            ),
            (
                authz,
                "authguard_scope_resolution_duration_seconds_count",
                "authguard_scope_resolutions_total",
            ),
        ]
        for metrics, histogram, counter in pairs:
            actual = cls.metric_sum(metrics, histogram)
            expected = cls.metric_sum(metrics, counter)
            if expected <= 0 or actual != expected:
                raise RuntimeError(
                    f"metric accounting mismatch: {histogram}={actual}, {counter}={expected}"
                )
        deliveries = cls.metric_sum(authz, "authguard_scope_deliveries_total")
        allowed = cls.metric_sum(
            authz,
            "authguard_http_requests_total",
            {
                "route": "envoy.service.auth.v3.Authorization/Check",
                "method": "gRPC",
                "status": "200",
            },
        )
        if deliveries != allowed:
            raise RuntimeError(
                f"scope deliveries {deliveries} differ from allowed Envoy Check calls {allowed}"
            )

    def _scrape_metrics(self, service: str) -> str:
        management = E2EOtherDefinitions.management()
        with self._forward_service(service, int(management["port"])) as port:
            with request.urlopen(
                f"http://127.0.0.1:{port}{management['metrics']['path']}", timeout=15
            ) as response:
                return response.read().decode()

    def _verify_counter_deltas(self) -> None:
        count = 3
        labels = {"route": "/api/v1/status", "method": "GET", "status": "200"}
        before = self.metric_sum(
            self._scrape_metrics(self.authguard_authz_service),
            "authguard_http_requests_total",
            labels,
        )
        with self._forward_service(self.authguard_authz_service, 9090) as port:
            for _ in range(count):
                status, _ = self._api_http(port, "/api/v1/status")
                self._expect_status("controlled management API request", status, 200)
        after = self.metric_sum(
            self._scrape_metrics(self.authguard_authz_service),
            "authguard_http_requests_total",
            labels,
        )
        if after - before != count:
            raise RuntimeError(
                f"AuthZ HTTP metric delta {after - before}, expected {count}"
            )
        labels = {"provider": "github", "operation": "authorize", "outcome": "success"}
        before = self.metric_sum(
            self._scrape_metrics(self.authguard_authn_service),
            "authguard_authn_flows_total",
            labels,
        )

        class NoRedirect(request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = request.build_opener(NoRedirect)
        with self._forward_service(self.authguard_authn_service, 8082) as port:
            for _ in range(count):
                outgoing = request.Request(
                    f"http://127.0.0.1:{port}/auth/oauth2/github/authorize?return_uri=%2Fcustomer-growth%2Fjobs",
                    headers={"Host": E2EOtherDefinitions.AUTHN_HOST},
                )
                try:
                    opener.open(outgoing, timeout=15)
                except error.HTTPError as response:
                    if response.code != 302:
                        raise
                    if not response.headers.get("Location"):
                        raise RuntimeError(
                            "controlled OAuth authorization returned no redirect"
                        )
                    response.close()
                else:
                    raise RuntimeError(
                        "controlled OAuth authorization did not redirect"
                    )
        after = self.metric_sum(
            self._scrape_metrics(self.authguard_authn_service),
            "authguard_authn_flows_total",
            labels,
        )
        if after - before != count:
            raise RuntimeError(
                f"AuthN authorization metric delta {after - before}, expected {count}"
            )
        self.details.append(
            "Three controlled AuthZ API calls and three AuthN authorize requests each incremented their labelled counter by exactly three"
        )
