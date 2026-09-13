"""Phase 21: verify DB, logs, metrics, Jaeger, cache, and runtime health."""

from __future__ import annotations

import json
from urllib import request

from common.kubernetes import WORKLOAD_IMAGES
from common.model import RunContext, VerificationResult
from verifier.base_verifier import BaseVerifier
from verifier.s20_observability_contract import (
    ADAPTER_LOG_EVENTS, AUTHN_LOG_EVENTS, AUTHZ_LOG_EVENTS,
    require_adapter_events, require_json_events, verify_authn_metrics, verify_authz_metrics,
)


class RuntimeEvidenceVerifier(BaseVerifier):
    scenario_id = "21"
    title = "Observability: PostgreSQL, logs, metrics, Jaeger, and runtime health"

    def run(self) -> VerificationResult:
        return self.execute(self.verify_runtime_evidence)

    def verify_runtime_evidence(self) -> None:
        """Verify persistent state plus metrics, logs, traces and runtime health."""
        self.step("query AuthN/AuthZ Prometheus metrics and runtime profiles", self._verify_metrics)
        self.step("validate AuthN/AuthZ and five SDK structured logs", self._verify_observability_logs)
        self.step("query Jaeger services and recent trace inventory", self._verify_jaeger_runtime_inventory)
        self.step("query PostgreSQL IAM state and schema isolation", self._verify_postgresql_schema_isolation)

    def _verify_jaeger_runtime_inventory(self) -> None:
        """Require persisted runtime traces from both AuthGuard services and every Biz app."""
        expected = {
            "authguard-authn",
            "authguard-authz",
            *{f"e2e-authguard-{component}" for component in WORKLOAD_IMAGES},
        }
        with self._forward_service(self.jaeger_service, 16686) as port:
            jaeger = self._jaeger_query(port)
            jaeger.require_services(expected)
            jaeger.require_recent_traces(expected)
        self.details.append(
            "Jaeger Query API contains recent traces from AuthN, AuthZ, and all five Biz services"
        )

    def _verify_metrics(self) -> None:
        with self._forward_service(self.authguard_release, 9091) as port:
            with request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=15) as response:
                metrics = response.read().decode()
            self._verify_management_diagnostics(port, metrics, "authguard-authz")
        verify_authz_metrics(metrics)
        with self._forward_service(f"{self.authguard_release}-authn", 8082) as port:
            with request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=15) as response:
                authn_metrics = response.read().decode()
            self._verify_management_diagnostics(port, authn_metrics, "authguard-authn")
        providers = tuple(
            flow["provider_id"] for flow in self.authn_scenarios["provider_flows"]
        )
        verify_authn_metrics(authn_metrics, providers, ("e2e-authguard-keycloak",))
        self.details.append(
            "Positive OpenMetrics samples verified independently from AuthN :8082 and "
            "AuthZ :9091: authorize/callback latency, allow/deny decisions, and "
            "direct/opaque scope delivery/resolution"
        )

    def _verify_management_diagnostics(
        self,
        port: int,
        configured_metrics: str,
        component: str,
    ) -> None:
        with request.urlopen(f"http://127.0.0.1:{port}/_/metrics", timeout=15) as response:
            canonical_metrics = response.read().decode()
        if "# HELP authguard_" not in canonical_metrics or "# HELP authguard_" not in configured_metrics:
            raise RuntimeError(f"{component}: management metric endpoints returned no registry")
        with request.urlopen(f"http://127.0.0.1:{port}/_/pprof", timeout=15) as response:
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
        if missing or not all(profile.get(name) is not None for name in required):
            raise RuntimeError(
                f"{component}: /_/pprof is missing runtime fields {sorted(missing)}"
            )
        self.details.append(
            f"{component} common management routes expose /_/metrics and bounded CPU/memory "
            "runtime diagnostics at /_/pprof"
        )

    def _verify_observability_logs(self) -> None:
        result = self._run(
            (
                "kubectl",
                "logs",
                "-n",
                self.namespace,
                "-l",
                "app.kubernetes.io/component=authz",
                "--tail=5000",
            )
        )
        authz_json_records = require_json_events(
            result.output,
            AUTHZ_LOG_EVENTS,
            "authguard-authz",
        )
        check_events = 0
        discovery_events: set[str] = set()
        provisioning_events: set[str] = set()
        discovery_providers: set[str] = set()
        for line in result.output.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            span = event.get("span", {})
            if (
                span.get("rpc.service") == "envoy.service.auth.v3.Authorization"
                and span.get("rpc.method") == "Check"
            ):
                check_events += 1
            discovery = event.get("fields", {}).get("authguard.principal.discovery")
            if discovery == "federation":
                discovery_events.add(discovery)
            provisioning = event.get("fields", {}).get("authguard.principal.provisioning")
            if provisioning == "SCIM":
                provisioning_events.add(provisioning)
            provider = event.get("fields", {}).get("authguard.principal.provider_id")
            if isinstance(provider, str):
                discovery_providers.add(provider)
        if check_events == 0:
            raise RuntimeError("Authguard logs contain no Envoy Authorization/Check events")
        missing_discovery = {"federation"} - discovery_events
        if missing_discovery:
            raise RuntimeError(
                "Authguard structured logs lack Principal discovery evidence: "
                + ", ".join(sorted(missing_discovery))
            )
        if "SCIM" not in provisioning_events:
            raise RuntimeError("Authguard structured logs lack SCIM push provisioning evidence")
        expected_providers = {"e2e-authguard-keycloak", "e2e-authguard-direct-ldap"}
        if missing := expected_providers - discovery_providers:
            raise RuntimeError(
                "Authguard structured logs lack provider-specific discovery evidence: "
                + ", ".join(sorted(missing))
            )
        self.details.append(
            f"Authguard structured logs contain {check_events} "
            "envoy.service.auth.v3.Authorization/Check events"
        )
        self.details.append(
            "Authguard structured logs contain Keycloak/LDAP pull federation and SCIM push "
            "materialization events"
        )
        authn_logs = self._run(
            (
                "kubectl",
                "logs",
                "-n",
                self.namespace,
                "-l",
                "app.kubernetes.io/component=authn",
                "--tail=5000",
            )
        ).output
        authn_json_records = require_json_events(
            authn_logs,
            AUTHN_LOG_EVENTS,
            "authguard-authn",
        )
        self.details.append(
            f"AuthN/AuthZ JSON contracts verified {authn_json_records}/{authz_json_records} "
            "records with explicit authorize, callback, provider normalization, account "
            "linking, ext_authz Check, and opaque scope-resolution lifecycle events"
        )

        for component in WORKLOAD_IMAGES:
            logs = self._run(
                (
                    "kubectl",
                    "logs",
                    "-n",
                    self.namespace,
                    "-l",
                    f"app.kubernetes.io/component=e2e-authguard-{component}",
                    "--tail=5000",
                )
            ).output
            require_adapter_events(logs, component)
        self.details.append(
            f"All {len(WORKLOAD_IMAGES)} SDK workloads emitted {len(ADAPTER_LOG_EVENTS)} "
            "required events covering direct-header resolver, opaque gRPC resolver, and "
            "resource-URN to parameterized SQL-scope translation"
        )

    def _verify_postgresql_schema_isolation(self) -> None:
        pod = self._postgresql_pod()
        sql = (
            "SELECT "
            "(SELECT count(*) FROM information_schema.schemata WHERE schema_name IN "
            "('e2e_authguard_customer_growth_go_sqlx','e2e_authguard_customer_growth_rust_sqlx','e2e_authguard_customer_growth_python_sqlalchemy','e2e_authguard_customer_growth_spring_jdbc','e2e_authguard_customer_growth_spring_jpa')) || '|' || "
            "(SELECT count(*) FROM information_schema.tables WHERE table_name='e2e_authguard_customer_growth_jobs' AND table_schema LIKE 'e2e_authguard_%') || '|' || "
            "CASE WHEN has_schema_privilege('e2e_authguard_customer_growth_go_sqlx','e2e_authguard_customer_growth_rust_sqlx','USAGE') "
            "THEN 1 ELSE 0 END || '|' || "
            "(SELECT count(*) FROM information_schema.tables WHERE table_schema='authguard' "
            "AND table_name LIKE 'iam_%') || '|' || "
            "(SELECT count(*) FROM authguard.iam_principal_identity) || '|' || "
            "(SELECT count(*) FROM authguard.iam_principal WHERE id IN "
            "('principal-direct-reader','principal-token-editor','principal-no-data-reader',"
            "'principal-direct-readers',"
            "'principal-token-editors','principal-growth-job-runner')) || '|' || "
            "(SELECT count(*) FROM authguard.iam_role) || '|' || "
            "(SELECT count(*) FROM authguard.iam_action) || '|' || "
            "(SELECT count(*) FROM authguard.iam_role_binding) || '|' || "
            "(SELECT count(*) FROM authguard.iam_authn_flow) || '|' || "
            "(SELECT count(*) FROM authguard.iam_principal_identity WHERE "
            "(provider='github' AND issuer='https://github.com' AND subject='987654') OR "
            "(provider='google' AND issuer='https://accounts.google.com' AND subject='google-editor-001') OR "
            "(provider='wechat' AND issuer='https://open.weixin.qq.com' AND subject='wechat-union-001') OR "
            "(provider='qq' AND issuer='https://graph.qq.com' AND subject='qq-open-001'))"
        )
        isolation = self._postgresql_query(pod, sql)
        if isolation != "5|5|0|7|13|6|2|4|6|0|4":
            raise RuntimeError(
                "PostgreSQL IAM/schema contract mismatch: expected "
                "5|5|0|7|13|6|2|4|6|0|4, "
                f"got {isolation!r}"
            )
        self.details.append(
            "five workload schemas remain isolated; one shared AuthGuard IAM schema contains "
            "seven canonical tables, six pre-authorized enterprise Principals, two roles, "
            "four actions, six role bindings, thirteen durable external-identity bindings "
            "across Keycloak/LDAP/SCIM/social Providers (including two exact "
            "SCIM/OIDC convergences), and no stale auth flow"
        )


def verify(context: RunContext) -> VerificationResult:
    return RuntimeEvidenceVerifier(context).run()
