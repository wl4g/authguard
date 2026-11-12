from __future__ import annotations
import json
import re
from util.images import E2EImagesDefinitions
from verifier.context import BaseVerifier, VerificationContext, VerificationResult


class E2ES42LogsVerifier(BaseVerifier):
    scenario_id = "42"
    title = "Observability: structured AuthN, AuthZ and SDK logs"

    def deploy(self, context: VerificationContext) -> None:
        """Reuse the deployment owned by scenario 00."""

    def init(self, context: VerificationContext) -> None:
        """No additional input initialization is required."""

    def verifier(self, context: VerificationContext) -> VerificationResult:
        return self.execute(self._verify)

    def _verify(self) -> None:
        self.step(
            "validate AuthN/AuthZ and five SDK structured logs",
            self._verify_observability_logs,
        )

    def _verify_observability_logs(self) -> None:
        authz_logs = self.infrastructure.service_logs(
            self.authguard_authz_service, tail=5000
        )
        authz_json_records = E2ES42LogsVerifier.require_json_events(
            authz_logs, E2ES42LogsVerifier.AUTHZ_LOG_EVENTS, "authguard-authz"
        )
        check_events = 0
        discovery_events: set[str] = set()
        provisioning_events: set[str] = set()
        discovery_providers: set[str] = set()
        for line in authz_logs.splitlines():
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
            provisioning = event.get("fields", {}).get(
                "authguard.principal.provisioning"
            )
            if provisioning == "SCIM":
                provisioning_events.add(provisioning)
            provider = event.get("fields", {}).get("authguard.principal.provider_id")
            if isinstance(provider, str):
                discovery_providers.add(provider)
        if check_events == 0:
            raise RuntimeError(
                "Authguard logs contain no Envoy Authorization/Check events"
            )
        missing_discovery = {"federation"} - discovery_events
        if missing_discovery:
            raise RuntimeError(
                "Authguard structured logs lack Principal discovery evidence: "
                + ", ".join(sorted(missing_discovery))
            )
        if "SCIM" not in provisioning_events:
            raise RuntimeError(
                "Authguard structured logs lack SCIM push provisioning evidence"
            )
        expected_providers = {"e2e-authguard-keycloak", "e2e-authguard-direct-ldap"}
        if missing := (expected_providers - discovery_providers):
            raise RuntimeError(
                "Authguard structured logs lack provider-specific discovery evidence: "
                + ", ".join(sorted(missing))
            )
        self.details.append(
            f"Authguard structured logs contain {check_events} envoy.service.auth.v3.Authorization/Check events"
        )
        self.details.append(
            "Authguard structured logs contain Keycloak/LDAP pull federation and SCIM push materialization events"
        )
        authn_logs = self.infrastructure.service_logs(
            self.authguard_authn_service, tail=5000
        )
        authn_json_records = E2ES42LogsVerifier.require_json_events(
            authn_logs, E2ES42LogsVerifier.AUTHN_LOG_EVENTS, "authguard-authn"
        )
        self.details.append(
            f"AuthN/AuthZ JSON contracts verified {authn_json_records}/{authz_json_records} records with explicit provider normalization, protocol-neutral account linking, ext_authz Check, and opaque scope-resolution lifecycle events"
        )
        for component in E2EImagesDefinitions.WORKLOADS:
            logs = self.infrastructure.service_logs(
                self.workload_service(component), tail=5000
            )
            E2ES42LogsVerifier.require_adapter_events(logs, component)
        self.details.append(
            f"All {len(E2EImagesDefinitions.WORKLOADS)} SDK workloads emitted {len(E2ES42LogsVerifier.ADAPTER_LOG_EVENTS)} required events covering direct-header resolver, opaque gRPC resolver, and resource-URN to parameterized SQL-scope translation"
        )

    AUTHN_LOG_EVENTS = frozenset(
        {
            "authguard.authn.provider.started",
            "authguard.authn.provider.succeeded",
            "authguard.authn.account_linking.started",
            "authguard.authn.account_linking.succeeded",
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

    @staticmethod
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
                f"{component} structured-log contract is missing events {sorted(missing)}; observed={sorted(observed)}"
            )
        return json_records

    @staticmethod
    def require_adapter_events(logs: str, component: str) -> None:
        """Require both resolver modes and SQL translation in each SDK workload log."""
        observed = set(re.findall("authguard\\.[a-z0-9_.]+", logs))
        missing = E2ES42LogsVerifier.ADAPTER_LOG_EVENTS - observed
        if missing:
            raise RuntimeError(
                f"{component} adapter-log contract is missing events {sorted(missing)}; observed={sorted(observed)}"
            )
