"""Disposable k3s deployment lifecycle for the gateway authorization E2E."""

from __future__ import annotations

from contextlib import contextmanager
import base64
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
from typing import Iterator
from urllib import error, parse, request

from .config import CONFIG_DIR, E2E_DIR, PROJECT_ROOT
from .model import CommandResult, RunContext
from .process import run_command
from .telemetry import E2ETrace
from verifier.s20_observability_contract import (
    ADAPTER_LOG_EVENTS,
    AUTHN_LOG_EVENTS,
    AUTHZ_LOG_EVENTS,
    AuthorizationJaegerTraceVerifier,
    AuthnJaegerTraceVerifier,
    ControlPlaneJaegerTraceVerifier,
    JaegerQueryClient,
    OidcJaegerTraceVerifier,
    require_adapter_events,
    require_json_events,
    verify_authn_metrics,
    verify_authz_metrics,
)


ALIYUN_ENVOY_IMAGE = (
    "registry.cn-shenzhen.aliyuncs.com/wl4g/envoyproxy_envoy:distroless-v1.36.4"
)
ALIYUN_ENVOY_GATEWAY_IMAGE = (
    "registry.cn-shenzhen.aliyuncs.com/wl4g/envoyproxy_gateway:v1.9.0"
)
ALIYUN_REDIS_IMAGE = (
    "registry.cn-shenzhen.aliyuncs.com/wl4g-k8s/bitnami_redis-cluster:7.0.14"
)
ALIYUN_KEYCLOAK_IMAGE = "registry.cn-shenzhen.aliyuncs.com/wl4g/keycloak:26.7.0"
ALIYUN_LDAP_IMAGE = "registry.cn-shenzhen.aliyuncs.com/wl4g/glauth:v2.5.0"
ALIYUN_JAEGER_IMAGE = (
    "registry.cn-shenzhen.aliyuncs.com/wl4g/jaegertracing_all-in-one:1.76.0"
)
ALIYUN_POSTGRES_IMAGE = (
    "registry.cn-shenzhen.aliyuncs.com/wl4g/bitnami_postgresql:18.3"
)
AUTHGUARD_IMAGE = "registry.cn-shenzhen.aliyuncs.com/wl4g/authguard:e2e-local"
AUTHGUARD_API_TOKEN = "e2e-authguard-api-token"
E2E_KEYS_DIR = CONFIG_DIR / "e2e-jwt-keys"
MOCK_IDP_IMAGE = (
    "registry.cn-shenzhen.aliyuncs.com/wl4g/e2e-authguard-customer-growth-mock-idp:e2e-local"
)
WORKLOAD_IMAGES = {
    "go-sqlx": "registry.cn-shenzhen.aliyuncs.com/wl4g/e2e-authguard-customer-growth-go-sqlx:e2e-local",
    "rust-sqlx": "registry.cn-shenzhen.aliyuncs.com/wl4g/e2e-authguard-customer-growth-rust-sqlx:e2e-local",
    "python-sqlalchemy": "registry.cn-shenzhen.aliyuncs.com/wl4g/e2e-authguard-customer-growth-python-sqlalchemy:e2e-local",
    "spring-jdbc": "registry.cn-shenzhen.aliyuncs.com/wl4g/e2e-authguard-customer-growth-spring-jdbc:e2e-local",
    "spring-jpa": "registry.cn-shenzhen.aliyuncs.com/wl4g/e2e-authguard-customer-growth-spring-jpa:e2e-local",
}
WORKLOAD_DIRECTORIES = {
    "go-sqlx": "golang-sqlx-service",
    "rust-sqlx": "rust-sqlx-service",
    "python-sqlalchemy": "python-sqlalchemy-service",
    "spring-jdbc": "springboot-jdbc-service",
    "spring-jpa": "springboot-jpa-service",
}
WORKLOAD_HOSTS = {
    component: f"e2e-authguard-{component}.customer-growth.local"
    for component in WORKLOAD_IMAGES
}
AUTHN_HOST = "e2e-authguard-authn.customer-growth.local"
LOCAL_PORT_RANGE = range(28800, 28900)
GROUP_EXTERNAL_IDS = {
    "direct-readers": "group:11111111-1111-4111-8111-111111111111",
    "token-editors": "group:22222222-2222-4222-8222-222222222222",
}
GROUP_PRINCIPAL_IDS = {
    "direct-readers": "principal-direct-readers",
    "token-editors": "principal-token-editors",
}


class KubernetesE2E:
    """Own one disposable namespace and the three Helm releases inside it."""

    def __init__(self, context: RunContext) -> None:
        self.context = context
        self.namespace = os.getenv(
            "AUTHGUARD_E2E_NAMESPACE", "e2e-authguard-customer-growth"
        )
        self.release = os.getenv(
            "AUTHGUARD_E2E_RELEASE", "e2e-authguard-customer-growth"
        )
        if not self.namespace.startswith("e2e-authguard-"):
            raise ValueError("AUTHGUARD_E2E_NAMESPACE must start with e2e-authguard-")
        if not self.release.startswith("e2e-authguard-"):
            raise ValueError("AUTHGUARD_E2E_RELEASE must start with e2e-authguard-")
        self.envoy_release = f"{self.release}-envoy"
        self.support_release = f"{self.release}-support"
        self.authguard_release = f"{self.release}-authguard"
        self.gateway_name = "e2e-authguard-customer-growth-gateway"
        self.environment = {
            "KUBECONFIG": os.getenv(
                "KUBECONFIG", str(Path.home() / ".kube" / "config")
            )
        }
        self.commands: list[CommandResult] = []
        self.details: list[str] = []
        self.authn_traces: dict[str, E2ETrace] = {}
        self.authn_trace_principals: dict[str, str] = {}
        self.api_trace_headers: dict[str, str] = {}
        self.helm_chart = PROJECT_ROOT / "deploy" / "helm" / "authguard"
        self.support_chart = E2E_DIR / "helm"
        self.deploy_dir = E2E_DIR / "deploy"
        scenario_fixture = json.loads(
            (CONFIG_DIR / "authguard-e2e-scenarios.json").read_text(encoding="utf-8")
        )
        if scenario_fixture.get("version") != 4:
            raise ValueError("AuthGuard E2E fixture version must be 4")
        self.authn_scenarios = scenario_fixture["authn"]
        self.principal_scenarios = scenario_fixture["principal_federation"]

    @property
    def keycloak_service(self) -> str:
        return f"{self.support_release}-keycloak"

    @property
    def postgresql_service(self) -> str:
        return f"{self.support_release}-postgresql"

    @property
    def jaeger_service(self) -> str:
        return f"{self.support_release}-jaeger"

    @property
    def ldap_service(self) -> str:
        return f"{self.support_release}-ldap"

    @property
    def principal_discovery_secret(self) -> str:
        return f"{self.support_release}-principal-discovery-credentials"[:63].rstrip("-")

    @property
    def mock_idp_service(self) -> str:
        return f"{self.support_release}-mock-idp"

    def workload_service(self, component: str) -> str:
        return f"{self.support_release}-{component}"

    @property
    def issuer(self) -> str:
        return (
            f"http://{self.keycloak_service}.{self.namespace}.svc.cluster.local:8080"
            "/realms/example-corp"
        )

    @property
    def authn_issuer(self) -> str:
        return "urn:authguard:e2e:authn"

    def verify_prerequisites(self) -> None:
        for executable in ("docker", "helm", "kubectl"):
            if shutil.which(executable) is None:
                raise RuntimeError(f"required executable is unavailable: {executable}")
        self._run(("kubectl", "version", "--client=true"))
        self._run(("kubectl", "get", "nodes"))
        self._k3s_command()

    def redeploy(self) -> None:
        self._run(("helm", "dependency", "list", str(self.helm_chart)))
        if self.context.clean:
            self._clean_previous_release()
        self._run(("kubectl", "create", "namespace", self.namespace), allowed_codes={0, 1})
        if self.context.build_images:
            self._build_images()
        self._prepare_external_images()
        self._install_envoy_gateway()
        self._remove_mutable_cluster_images()
        self._install_support_services()
        # Create the consumer Pods first, then import each mutable local image.
        # Under image-GC pressure an unreferenced image can disappear while the
        # remaining large images are still being imported. Pending Pods pin the
        # image as soon as it becomes available and remove that race.
        self._prepare_workload_images()
        self._wait_for_support_services()
        self._import_image(AUTHGUARD_IMAGE)
        # Redis is installed by the Authguard chart with pullPolicy=Never. Import it
        # immediately before Helm creates the StatefulSet so k3s image GC cannot
        # collect an unreferenced image while the support services are starting.
        self._import_image(ALIYUN_REDIS_IMAGE)
        self._install_authguard()
        self._wait_for_resources()
        self._verify_redis_cluster()
        self._verify_running_images()
        self._verify_zero_container_restarts()

    def verify_principal_preauthorization(self) -> None:
        """Materialize enterprise identities and apply grants before business login."""
        self._verify_envoy_runtime_filter_chain()
        trace = E2ETrace("customer-growth.administrator-preauthorization.e2e")
        span = trace.start_client(
            "authz.administrator.preauthorization",
            **{"server.address": "authguard-management.local"},
        )
        self.api_trace_headers = {
            "traceparent": span.traceparent,
            "x-request-id": trace.request_id,
        }
        try:
            self._bootstrap_authorization_policy()
        finally:
            self.api_trace_headers = {}
            span.finish()
            trace.finish()
        self._export_verifier_trace(trace)
        verifier = ControlPlaneJaegerTraceVerifier()
        with self._forward_service(self.jaeger_service, 16686) as query_port:
            payload = self._jaeger_query(query_port).wait_for_trace(trace, verifier)
        verifier.verify(payload, trace)
        self.details.extend(
            [
                "Jaeger Query API verified administrator federation, materialization, and "
                "revision-checked policy calls in AuthZ",
                f"administrator Jaeger trace ID: {trace.trace_id}",
            ]
        )

    def verify_authentication(self) -> None:
        """Exercise OAuth-like AuthN normalization and durable account linking."""
        envoy_service = self._envoy_proxy_service()
        with (
            self._forward_service(envoy_service, 8082) as authn_gateway_port,
            self._forward_service(self.mock_idp_service, 8080) as mock_idp_port,
        ):
            first_logins = {
                flow["provider_id"]: self._social_login(
                    authn_gateway_port,
                    mock_idp_port,
                    flow["provider_id"],
                    flow["external_identity"].get("username"),
                    flow["expected_principal"]["trusted_claims"],
                )
                for flow in self.authn_scenarios["provider_flows"]
            }

        # A second login proves the durable identity binding resolves back to
        # the same Principal without unsafe email matching.
        with (
            self._forward_service(envoy_service, 8082) as authn_gateway_port,
            self._forward_service(self.mock_idp_service, 8080) as mock_idp_port,
        ):
            repeated_logins = {
                flow["provider_id"]: self._social_login(
                    authn_gateway_port,
                    mock_idp_port,
                    flow["provider_id"],
                    flow["external_identity"].get("username"),
                    flow["expected_principal"]["trusted_claims"],
                )
                for flow in self.authn_scenarios["provider_flows"]
            }
        for provider, first in first_logins.items():
            repeated = repeated_logins[provider]
            if first["principal"]["principalId"] != repeated["principal"]["principalId"]:
                raise RuntimeError("repeated social login created a duplicate Principal")
        self._verify_authn_distributed_traces()

    def verify_gateway_authorization(self) -> None:
        """Verify pre-authorized user/workload requests through Envoy and AuthZ."""
        with self._forward_service(self.keycloak_service, 8080) as keycloak_port:
            direct_external_token = self._password_token(
                keycloak_port, "direct-reader", "direct-reader-password"
            )
            editor_external_token = self._password_token(
                keycloak_port, "token-editor", "token-editor-password"
            )
            no_data_external_token = self._password_token(
                keycloak_port, "no-data-reader", "no-data-reader-password"
            )
        envoy_service = self._envoy_proxy_service()
        with self._forward_service(envoy_service, 8082) as authn_gateway_port:
            oidc_trace = E2ETrace("customer-growth.authentication.oidc.e2e")
            oidc_span = oidc_trace.start_client("envoy.authn.oidc")
            direct_token = self._canonicalize_token(
                authn_gateway_port,
                direct_external_token,
                "USER",
                headers={
                    "traceparent": oidc_span.traceparent,
                    "x-request-id": oidc_trace.request_id,
                },
            )
            oidc_span.finish()
            oidc_trace.finish()
            editor_token = self._canonicalize_token(
                authn_gateway_port, editor_external_token, "USER"
            )
            no_data_token = self._canonicalize_token(
                authn_gateway_port, no_data_external_token, "USER"
            )
        self._export_verifier_trace(oidc_trace)
        with self._forward_service(self.jaeger_service, 16686) as query_port:
            oidc_verifier = OidcJaegerTraceVerifier("principal-direct-reader")
            oidc_payload = self._jaeger_query(query_port).wait_for_trace(
                oidc_trace, oidc_verifier
            )
        oidc_verifier.verify(oidc_payload, oidc_trace)
        self.details.append(
            "Jaeger verified Keycloak OIDC token normalization through Envoy/AuthN to "
            "canonical principal-direct-reader"
        )
        for token, principal_id in (
            (direct_token, "principal-direct-reader"),
            (editor_token, "principal-token-editor"),
            (no_data_token, "principal-no-data-reader"),
        ):
            if self._jwt_claims(token).get("principal_id") != principal_id:
                raise RuntimeError(f"AuthN canonical token did not contain {principal_id!r}")

        with (
            self._forward_service(envoy_service, 80) as gateway_port,
            self._forward_service(envoy_service, 8082) as authn_gateway_port,
        ):
            self._verify_jwt_gate_precedes_ext_auth(
                gateway_port,
                next(iter(WORKLOAD_HOSTS.values())),
                direct_token,
            )
            for component, host in WORKLOAD_HOSTS.items():
                self._verify_workload_contract(
                    gateway_port,
                    component,
                    host,
                    direct_token,
                    editor_token,
                    no_data_token,
                )
                self._verify_distributed_trace(
                    gateway_port, component, host, direct_token
                )
            self._verify_create_denied_by_authz(
                gateway_port, direct_token, editor_token
            )
            self._verify_workload_client_credentials(gateway_port, authn_gateway_port)
            self._verify_resign_token_boundary(gateway_port, direct_token)
            self._verify_route_matcher_denials()

    def verify_runtime_evidence(self) -> None:
        """Verify persistent state plus metrics, logs, traces and runtime health."""
        self._verify_metrics()
        self._verify_observability_logs()
        self._verify_jaeger_runtime_inventory()
        self._verify_postgresql_schema_isolation()

    def _social_login(
        self,
        authn_gateway_port: int,
        mock_idp_port: int,
        provider: str,
        expected_username: str | None,
        trusted_claims: dict[str, object],
    ) -> dict:
        """Drive browser redirects through Envoy and a real OAuth-like adapter flow."""

        trace = E2ETrace(
            "customer-growth.authentication.e2e",
            request_id=f"e2e-authguard-authn-{provider}-{os.urandom(6).hex()}",
        )

        class NoRedirect(request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = request.build_opener(NoRedirect)

        def redirect_location(
            url: str,
            *,
            host: str | None = None,
            headers: dict[str, str] | None = None,
        ) -> str:
            headers = {**({"Host": host} if host else {}), **(headers or {})}
            outgoing = request.Request(url, headers=headers)
            try:
                opener.open(outgoing, timeout=15)
            except error.HTTPError as response:
                if response.code not in (302, 303, 307, 308):
                    raise
                location = response.headers.get("Location")
                if location:
                    return location
            raise RuntimeError(f"expected OAuth redirect from {url}")

        authorize_span = trace.start_client(
            "envoy.authn.authorize",
            **{
                "server.address": AUTHN_HOST,
                "http.request.method": "GET",
            },
        )
        authorize_location = redirect_location(
            f"http://127.0.0.1:{authn_gateway_port}/auth/v1/providers/{provider}/authorize"
            "?return_uri=%2Fcustomer-growth%2Fjobs",
            host=AUTHN_HOST,
            headers={
                "traceparent": authorize_span.traceparent,
                "x-request-id": trace.request_id,
            },
        )
        authorize_span.finish()
        provider_url = parse.urlsplit(authorize_location)
        callback_location = redirect_location(
            f"http://127.0.0.1:{mock_idp_port}{provider_url.path}"
            + (f"?{provider_url.query}" if provider_url.query else "")
        )
        callback_url = parse.urlsplit(callback_location)
        callback_span = trace.start_client(
            "envoy.authn.callback",
            **{
                "server.address": AUTHN_HOST,
                "http.request.method": "GET",
            },
        )
        outgoing = request.Request(
            f"http://127.0.0.1:{authn_gateway_port}{callback_url.path}"
            + (f"?{callback_url.query}" if callback_url.query else ""),
            headers={
                "Host": AUTHN_HOST,
                "traceparent": callback_span.traceparent,
                "x-request-id": trace.request_id,
            },
        )
        with request.urlopen(outgoing, timeout=20) as response:
            if response.status != 200:
                raise RuntimeError(f"AuthN callback returned HTTP {response.status}")
            login = json.loads(response.read())
        callback_span.finish()
        trace.finish()
        self.authn_traces[provider] = trace
        claims = self._jwt_claims(login.get("accessToken", ""))
        principal = login.get("principal", {})
        provider_claims = {"id", "openid", "unionid", "access_token", "authorization_code"}
        if (
            claims.get("iss") != self.authn_issuer
            or claims.get("aud") != "customer-growth-job-service"
            or claims.get("principal_id") != principal.get("principalId")
            or claims.get("principal_kind") != "USER"
            or claims.get("authguard_group_ids") != []
            or provider_claims.intersection(claims)
        ):
            raise RuntimeError(f"{provider}: AuthN emitted an invalid canonical Principal token")
        if any(claims.get(name) != value for name, value in trusted_claims.items()):
            raise RuntimeError(f"{provider}: AuthN emitted invalid trusted claims")
        if expected_username is not None and claims.get("username") != expected_username:
            raise RuntimeError(f"{provider}: AuthN emitted an invalid normalized username")
        self.authn_trace_principals[provider] = principal["principalId"]
        self.details.append(
            f"{provider}: Envoy -> AuthN callback -> token exchange -> identity lookup -> "
            "ExternalIdentity -> durable identity binding -> canonical Principal succeeded"
        )
        return login

    def _bootstrap_authorization_policy(self) -> None:
        """Apply administrator grants to federated enterprise Principals."""
        with self._forward_service(self.authguard_release, 9091) as port:
            canonical_principals = self._materialize_scenario_principals(port)
            self._verify_direct_ldap_principal_discovery(port)
            self._verify_scim_push_provisioning(port, canonical_principals)
            self._required_group_principal_ids(port)

            status, body = self._api_http(port, "/api/v1/policy")
            self._expect_status("read bootstrap policy", status, 200)
            revision = json.loads(body)["revision"]
            replacement = self._authorization_policy(
                revision=revision,
                user_principal_ids={
                    username: principal["id"]
                    for username, principal in canonical_principals["users"].items()
                },
            )
            status, body = self._api_http(
                port,
                "/api/v1/policy",
                method="PUT",
                headers={"If-Match": str(revision)},
                json_body=replacement,
            )
            self._expect_status("bind projected principals atomically", status, 200)
            persisted = json.loads(body)
            if persisted.get("revision", 0) <= revision:
                raise RuntimeError("policy replacement did not advance its revision")
            self.details.append(
                "administrator pre-authorization bound federated canonical user/workload "
                "Principals in one revision-checked policy replacement before business login"
            )

    def _materialize_scenario_principals(
        self,
        api_port: int,
    ) -> dict[str, dict[str, dict]]:
        """Federate and materialize enterprise users, groups, and workloads."""
        resolved: dict[str, dict[str, dict]] = {"users": {}, "groups": {}}
        keycloak = self.principal_scenarios["keycloak"]
        provider_id = keycloak["provider_id"]
        for user in keycloak["users"]:
            candidate = self._search_external_principal(
                api_port,
                provider_id=provider_id,
                identity=user,
                expected_issuer=self.issuer,
                expected_external_id=user["external_id"],
            )
            resolved["users"][user["username"]] = self._materialize_idempotently(
                api_port, candidate, user["principal_id"]
            )
        for group in keycloak["groups"]:
            group_name = group["username"]
            group_candidate = self._search_external_principal(
                api_port,
                provider_id=provider_id,
                identity=group,
                expected_issuer=self.issuer,
                expected_external_id=group["external_id"],
            )
            resolved["groups"][group_name] = self._materialize_idempotently(
                api_port, group_candidate, group["principal_id"]
            )

        workload = keycloak["workload"]
        workload_candidate = self._search_external_principal(
            api_port,
            provider_id=provider_id,
            identity=workload,
            expected_issuer=self.issuer,
        )
        self._materialize_idempotently(
            api_port, workload_candidate, workload["principal_id"]
        )

        self.details.append(
            "the optional Keycloak integration federated and materialized "
            f"{len(resolved['users'])} users, {len(resolved['groups'])} groups, and one "
            "workload before administrator pre-authorization"
        )
        return resolved

    def _verify_direct_ldap_principal_discovery(self, port: int) -> None:
        """Prove native LDAP discovery without making Keycloak an LDAP dependency."""
        fixture = self.principal_scenarios["ldap"]
        identity = fixture["identity"]
        direct = fixture["direct"]
        ldap_candidate = self._search_external_principal(
            port,
            provider_id=direct["provider_id"],
            identity=identity,
            expected_issuer=direct["issuer"],
            expected_external_id=identity["immutable_external_id"],
        )
        self._materialize_idempotently(
            port, ldap_candidate, direct["principal_id"]
        )
        self.details.append(
            "Authguard direct LDAP (RFC 4511) discovery resolved a directory identity "
            "by stable POSIX uidNumber and materialized it idempotently; Keycloak remains "
            "an independent optional IdP integration"
        )

    def _verify_scim_push_provisioning(
        self,
        port: int,
        canonical_principals: dict[str, dict[str, dict]],
    ) -> None:
        """Prove SCIM lifecycle and exact external-identity convergence."""
        fixture = self.principal_scenarios["scim"]
        user_payload = json.loads(json.dumps(fixture["user"]))
        group_payload = json.loads(json.dumps(fixture["group"]))

        self._verify_scim_lifecycle(
            port,
            payload=user_payload,
            expected_kind="USER",
        )
        self._verify_scim_lifecycle(
            port,
            payload=group_payload,
            expected_kind="GROUP",
        )

        canonical_user = canonical_principals["users"]["direct-reader"]
        converged_user = json.loads(json.dumps(user_payload))
        converged_user["resource"].update(
            {
                "id": "scim-canonical-user-convergence",
                "externalId": self.principal_scenarios["keycloak"]["users"][0]["external_id"],
                "userName": "direct-reader",
                "displayName": "Direct Reader",
            }
        )
        projected = self._scim_event(port, converged_user, create=True)
        if projected["id"] != canonical_user["id"]:
            raise RuntimeError("SCIM User did not converge on the canonical OIDC Principal")
        self._get_principal(port, canonical_user["id"])

        canonical_group = canonical_principals["groups"]["direct-readers"]
        converged_group = json.loads(json.dumps(group_payload))
        converged_group["resource"].update(
            {
                "id": "scim-canonical-group-convergence",
                "externalId": self.principal_scenarios["keycloak"]["groups"][0]["external_id"],
                "displayName": "Direct Readers",
            }
        )
        projected = self._scim_event(port, converged_group, create=True)
        if projected["id"] != canonical_group["id"]:
            raise RuntimeError("SCIM Group did not converge on the canonical OIDC Principal")
        self._get_principal(port, canonical_group["id"])
        self.details.extend(
            [
                "SCIM RFC 7643 User and Group resources were idempotent across "
                "upsert, disable, and reactivation lifecycle transitions",
                "SCIM and OIDC materialization converged only through the exact "
                "(provider, issuer, externalId) identity key, never through email",
            ]
        )

    def _verify_scim_lifecycle(
        self,
        port: int,
        *,
        payload: dict,
        expected_kind: str,
    ) -> None:
        first = self._scim_event(port, payload, create=True)
        principal_id = first["id"]
        payload["principal_id"] = principal_id
        second = self._scim_event(port, payload)
        if first["id"] != second["id"]:
            raise RuntimeError(f"SCIM {expected_kind} upsert was not idempotent")
        active = self._get_principal(port, principal_id)
        if active.get("kind") != expected_kind or active.get("status") != "ACTIVE":
            raise RuntimeError(f"SCIM {expected_kind} Principal is not active")
        if active["id"] != first["id"]:
            raise RuntimeError(f"SCIM {expected_kind} lookup returned a different projection")

        self._scim_delete(
            port,
            principal_id,
            expected_kind,
        )
        disabled = self._get_principal(port, principal_id)
        if disabled.get("kind") != expected_kind or disabled.get("status") != "DISABLED":
            raise RuntimeError(f"SCIM {expected_kind} Principal was not tombstoned")
        if disabled["id"] != first["id"]:
            raise RuntimeError(f"SCIM {expected_kind} tombstone changed its local identifier")

        reactivated = self._scim_event(port, payload, create=True)
        if reactivated["id"] != first["id"]:
            raise RuntimeError(f"SCIM {expected_kind} upsert did not reactivate its tombstone")
        if expected_kind == "USER" and reactivated.get("active") is not True:
            raise RuntimeError("SCIM USER reactivation did not restore active=true")
        if expected_kind == "GROUP" and "active" in reactivated:
            raise RuntimeError("SCIM GROUP response exposed non-standard active attribute")

    def _search_external_principal(
        self,
        port: int,
        *,
        provider_id: str,
        identity: dict,
        expected_issuer: str,
        expected_external_id: str | None = None,
    ) -> dict:
        status, body = self._api_http(
            port,
            "/api/v1/principal-discovery/search",
            method="POST",
            json_body={
                "text": identity["username"],
                "kinds": [identity["expected_kind"]],
                "provider_ids": [provider_id],
                "per_provider_limit": 20,
                "cursors": {},
            },
        )
        self._expect_status(f"federated Principal search via {provider_id}", status, 200)
        candidates = []
        lookup_name = identity["username"]
        for candidate in json.loads(body).get("principals", []):
            reference = candidate.get("reference", {})
            if (
                reference.get("provider_id") == provider_id
                and reference.get("issuer") == expected_issuer
                and lookup_name
                in {candidate.get("username"), candidate.get("display_name")}
            ):
                candidates.append(candidate)
        if expected_external_id is not None:
            candidates = [
                candidate
                for candidate in candidates
                if candidate["reference"].get("external_id") == expected_external_id
            ]
        if len(candidates) != 1:
            raise RuntimeError(
                f"{provider_id}: expected exactly one matching federated Principal, "
                f"found {len(candidates)}"
            )
        candidate = candidates[0]
        if (
            candidate.get("kind") != identity["expected_kind"]
            or candidate.get("enabled") is not True
            or not candidate["reference"].get("external_id")
        ):
            raise RuntimeError(
                f"{provider_id}: federated Principal attributes do not match fixture"
            )
        for field in ("display_name", "email"):
            if field in identity and candidate.get(field) != identity[field]:
                raise RuntimeError(
                    f"{provider_id}: federated Principal {field} does not match fixture"
                )
        return candidate

    def _materialize_idempotently(
        self, port: int, candidate: dict, principal_id: str
    ) -> dict:
        reference = candidate["reference"]
        persisted: list[dict] = []
        for attempt in (1, 2):
            status, body = self._api_http(
                port,
                "/api/v1/principal-discovery/materialize",
                method="POST",
                json_body={"principal_id": principal_id, "reference": reference},
            )
            self._expect_status(
                f"materialize {reference['provider_id']} attempt {attempt}", status, 201
            )
            persisted.append(json.loads(body))
        if persisted[0]["id"] != persisted[1]["id"]:
            raise RuntimeError(
                f"{reference['provider_id']}: repeated materialization changed local identifier"
            )
        local = self._get_principal(port, principal_id)
        if local["id"] != persisted[0]["id"]:
            raise RuntimeError(
                f"{reference['provider_id']}: materialized projection cannot be resolved exactly"
            )
        return local

    def _get_principal(self, port: int, principal_id: str) -> dict:
        encoded_id = parse.quote(principal_id, safe="")
        status, body = self._api_http(port, f"/api/v1/principals/{encoded_id}")
        self._expect_status(f"read canonical Principal {principal_id}", status, 200)
        principal = json.loads(body)
        if principal.get("id") != principal_id:
            raise RuntimeError("Principal lookup returned a different canonical identifier")
        return principal

    def _scim_event(self, port: int, payload: dict, *, create: bool = False) -> dict:
        operation = payload["operation"]
        resource_kind = "Users" if operation == "upsert_user" else "Groups"
        resource = dict(payload["resource"])
        schema = (
            "urn:ietf:params:scim:schemas:core:2.0:User"
            if resource_kind == "Users"
            else "urn:ietf:params:scim:schemas:core:2.0:Group"
        )
        resource.setdefault("schemas", [schema])
        resource.pop("id", None)
        path = f"/scim/v2/{resource_kind}"
        method = "POST"
        expected_status = 201
        if not create:
            principal_id = parse.quote(payload["principal_id"], safe="")
            path = f"{path}/{principal_id}"
            method = "PUT"
            expected_status = 200
        status, body = self._api_http(
            port,
            path,
            method=method,
            json_body=resource,
        )
        self._expect_status(f"SCIM {operation}", status, expected_status)
        projected = json.loads(body)
        if not isinstance(projected, dict) or not projected.get("id"):
            raise RuntimeError("SCIM resource operation did not return a persisted Principal")
        return projected

    def _scim_delete(self, port: int, principal_id: str, kind: str) -> None:
        resource_kind = "Users" if kind == "USER" else "Groups"
        encoded_id = parse.quote(principal_id, safe="")
        status, _ = self._api_http(
            port,
            f"/scim/v2/{resource_kind}/{encoded_id}",
            method="DELETE",
        )
        self._expect_status(f"SCIM delete {kind}", status, 204)

    def _list_principals(self, port: int) -> list[dict]:
        status, body = self._api_http(port, "/api/v1/principals?limit=1000")
        self._expect_status("list local Principals", status, 200)
        return json.loads(body).get("items", [])

    def _required_group_principal_ids(self, port: int) -> dict[str, str]:
        for principal_id in GROUP_PRINCIPAL_IDS.values():
            principal = self._get_principal(port, principal_id)
            if principal.get("kind") != "GROUP" or principal.get("status") != "ACTIVE":
                raise RuntimeError(f"canonical group Principal {principal_id!r} is not active")
        return dict(GROUP_PRINCIPAL_IDS)

    def _verify_workload_contract(
        self,
        gateway_port: int,
        component: str,
        host: str,
        direct_token: str,
        editor_token: str,
        no_data_token: str,
    ) -> None:
        label = f"e2e-authguard-{component}"
        status, _ = self._http(gateway_port, host, "/customer-growth/jobs")
        self._expect_status(f"{label}: missing JWT", status, 401)

        status, body = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs",
            headers={"Authorization": f"Bearer {direct_token}"},
        )
        self._expect_status(f"{label}: direct context list", status, 200)
        self._expect_job_ids(f"{label}: direct context list", body, [1, 2, 3, 6])

        status, body = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs",
            headers={"Authorization": f"Bearer {editor_token}"},
        )
        self._expect_status(f"{label}: opaque token list", status, 200)
        self._expect_job_ids(f"{label}: opaque token list", body, [1, 3, 6])

        status, body = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs",
            headers={"Authorization": f"Bearer {no_data_token}"},
        )
        self._expect_status(f"{label}: LIST action with empty data scope", status, 200)
        self._expect_job_ids(f"{label}: empty data scope hides every seeded row", body, [])

        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/2",
            headers={"Authorization": f"Bearer {editor_token}"},
        )
        self._expect_status(f"{label}: explicit URN deny is hidden", status, 404)

        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/5",
            headers={
                "Authorization": f"Bearer {direct_token}",
                "x-authguard-context": "forged-client-context",
            },
        )
        self._expect_status(f"{label}: forged context is removed", status, 404)

        created = {
            "id": 101,
            "region": "global",
            "tenant_id": "example-corp",
            "workspace_id": "customer-insights",
            "project_id": "retention-analytics",
            "job_id": "monthly-retention-review",
            "display_name": "Monthly retention review",
            "status": "READY",
            "owner_user_id": "token-editor",
        }
        status, body = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs",
            method="POST",
            headers={"Authorization": f"Bearer {editor_token}"},
            json_body=created,
        )
        self._expect_status(f"{label}: authorized create", status, 200)
        if json.loads(body)["job_id"] != created["job_id"]:
            raise RuntimeError(f"{label}: authorized create returned the wrong job")

        status, body = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/101",
            method="PUT",
            headers={"Authorization": f"Bearer {editor_token}"},
            json_body={
                "display_name": "Monthly retention review v2",
                "status": "PAUSED",
                "owner_user_id": "token-editor",
            },
        )
        self._expect_status(f"{label}: authorized update", status, 200)
        if json.loads(body)["status"] != "PAUSED":
            raise RuntimeError(f"{label}: authorized update did not persist")

        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/101",
            method="DELETE",
            headers={"Authorization": f"Bearer {editor_token}"},
        )
        self._expect_status(f"{label}: authorized delete", status, 204)
        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/101",
            headers={"Authorization": f"Bearer {editor_token}"},
        )
        self._expect_status(f"{label}: deleted row stays absent", status, 404)

        # One deterministic outside-world probe: DELETE is an enumerated
        # customer-growth action but is NOT route-mapped, so the route
        # matcher itself must deny it before any resign/replace machinery
        # runs. The request pattern never mutates the backend.
        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/1",
            method="PATCH",
            headers={"Authorization": f"Bearer {direct_token}"},
        )
        self._expect_status(f"{label}: unmapped method is route-denied", status, 403)

        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/not-mapped",
            headers={"Authorization": f"Bearer {direct_token}"},
        )
        self._expect_status(f"{label}: unmapped path is gateway route-not-found", status, 404)

        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/1",
            method="PUT",
            headers={"Authorization": f"Bearer {direct_token}"},
            json_body={
                "display_name": "forbidden update",
                "status": "FAILED",
                "owner_user_id": "direct-reader",
            },
        )
        self._expect_status(f"{label}: read-only update is forbidden", status, 403)
        status, body = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/1",
            headers={"Authorization": f"Bearer {editor_token}"},
        )
        self._expect_status(f"{label}: rejected update preserves row", status, 200)
        if json.loads(body)["status"] != "READY":
            raise RuntimeError(f"{label}: rejected update changed the database")

        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/1",
            method="DELETE",
            headers={"Authorization": f"Bearer {direct_token}"},
        )
        self._expect_status(f"{label}: read-only delete is forbidden", status, 403)
        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/1",
            headers={"Authorization": f"Bearer {editor_token}"},
        )
        self._expect_status(f"{label}: rejected delete preserves row", status, 200)

    def _verify_create_denied_by_authz(
        self, gateway_port: int, read_token: str, editor_token: str
    ) -> None:
        """Prove every forbidden create terminates at AuthZ, before Biz persistence."""
        payload = {
            "id": 102,
            "region": "global",
            "tenant_id": "example-corp",
            "workspace_id": "customer-insights",
            "project_id": "retention-analytics",
            "job_id": "forbidden-create",
            "display_name": "Must not be created",
            "status": "READY",
            "owner_user_id": "direct-reader",
        }
        with self._forward_envoy_admin() as envoy_admin_port:
            before_envoy = self._envoy_auth_counters(envoy_admin_port)
            before_checks = self._authorization_check_count()
            before_denied = sum(self._authorization_denied_reasons().values())
            for component, host in WORKLOAD_HOSTS.items():
                status, _ = self._http(
                    gateway_port,
                    host,
                    "/customer-growth/jobs",
                    method="POST",
                    headers={"Authorization": f"Bearer {read_token}"},
                    json_body=payload,
                )
                self._expect_status(f"{component}: create denied by AuthZ", status, 403)
            after_envoy = self._envoy_auth_counters(envoy_admin_port)
        if self._authorization_check_count() - before_checks != len(WORKLOAD_HOSTS):
            raise RuntimeError("forbidden creates did not map one-to-one to AuthZ Check calls")
        self._expect_counter_delta(
            "forbidden create Envoy ext_authz.denied",
            before_envoy,
            after_envoy,
            "ext_auth_denied",
            len(WORKLOAD_HOSTS),
        )
        if sum(self._authorization_denied_reasons().values()) - before_denied != len(
            WORKLOAD_HOSTS
        ):
            raise RuntimeError("AuthZ denial metrics did not record every forbidden create")
        for component, host in WORKLOAD_HOSTS.items():
            status, _ = self._http(
                gateway_port,
                host,
                "/customer-growth/jobs/102",
                headers={"Authorization": f"Bearer {editor_token}"},
            )
            self._expect_status(f"{component}: rejected create did not mutate Biz DB", status, 404)

    def _clean_previous_release(self) -> None:
        for release in (
            self.authguard_release,
            self.support_release,
            self.envoy_release,
        ):
            self._run(
                (
                    "helm",
                    "uninstall",
                    release,
                    "-n",
                    self.namespace,
                    "--wait",
                    "--timeout=90s",
                ),
                allowed_codes={0, 1},
            )
        self._run(
            (
                "kubectl",
                "delete",
                "namespace",
                self.namespace,
                "--ignore-not-found=true",
                "--wait=false",
            )
        )
        deadline = time.monotonic() + self.context.timeout_seconds
        while time.monotonic() < deadline:
            existing = self._run(
                ("kubectl", "get", "namespace", self.namespace, "-o", "name"),
                allowed_codes={0, 1},
            )
            if existing.return_code != 0:
                return
            time.sleep(1)
        raise RuntimeError(f"timed out deleting namespace {self.namespace}")

    def _build_images(self) -> None:
        proxy = os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY")
        build_args: tuple[str, ...] = ()
        if proxy:
            parsed_proxy = parse.urlparse(proxy)
            if not parsed_proxy.hostname or not parsed_proxy.port:
                raise ValueError(
                    "HTTPS_PROXY/HTTP_PROXY must include a host and port"
                )
            proxy_host = parsed_proxy.hostname
            container_proxy = proxy
            if proxy_host in {"127.0.0.1", "localhost", "::1"}:
                proxy_host = "host.containers.internal"
                container_proxy = parse.urlunparse(
                    parsed_proxy._replace(
                        netloc=f"{proxy_host}:{parsed_proxy.port}"
                    )
                )
            build_args = (
                "--build-arg",
                f"HTTPS_PROXY={container_proxy}",
                "--build-arg",
                f"HTTP_PROXY={container_proxy}",
                "--build-arg",
                f"MAVEN_PROXY_HOST={proxy_host}",
                "--build-arg",
                f"MAVEN_PROXY_PORT={parsed_proxy.port}",
            )
        self._run(
            (
                "docker",
                "build",
                "--network=host",
                "--pull=false",
                *build_args,
                "-f",
                str(PROJECT_ROOT / "deploy" / "docker" / "Dockerfile"),
                "-t",
                AUTHGUARD_IMAGE,
                ".",
            ),
            cwd=PROJECT_ROOT,
        )
        for component, image in WORKLOAD_IMAGES.items():
            service_dir = self.deploy_dir / WORKLOAD_DIRECTORIES[component]
            self._run(
                (
                    "docker",
                    "build",
                    "--network=host",
                    "--pull=false",
                    *build_args,
                    "-f",
                    str(service_dir / "Dockerfile"),
                    "-t",
                    image,
                    ".",
                ),
                cwd=PROJECT_ROOT,
            )
        self._run(
            (
                "docker",
                "build",
                "--network=host",
                "--pull=false",
                *build_args,
                "-f",
                str(self.deploy_dir / "mocksvc-idp-service" / "Dockerfile"),
                "-t",
                MOCK_IDP_IMAGE,
                ".",
            ),
            cwd=PROJECT_ROOT,
        )

    def _prepare_external_images(self) -> None:
        external_images = (
            ALIYUN_ENVOY_IMAGE,
            ALIYUN_ENVOY_GATEWAY_IMAGE,
            ALIYUN_REDIS_IMAGE,
            ALIYUN_KEYCLOAK_IMAGE,
            ALIYUN_LDAP_IMAGE,
            ALIYUN_JAEGER_IMAGE,
            ALIYUN_POSTGRES_IMAGE,
        )
        cluster_images = set(
            self._run(
                (*self._k3s_command(), "ctr", "-n", "k8s.io", "images", "list", "-q")
            ).output.splitlines()
        )
        for image in external_images:
            if image in cluster_images:
                self.details.append(f"reuse k3s image: {image}")
                continue
            inspected = self._run(
                # Docker returns 1 for a missing image; the Podman-compatible
                # Docker CLI returns 125 for the same non-fatal cache miss.
                ("docker", "image", "inspect", image), allowed_codes={0, 1, 125}
            )
            if inspected.return_code != 0:
                self._run(("docker", "pull", image))
            self._import_image(image)

    def _prepare_workload_images(self) -> None:
        # e2e-local tags are intentionally mutable. Import them immediately before
        # creating their Pods so k3s image GC cannot collect an unreferenced image
        # while an earlier Helm release is still becoming ready.
        for image in (*WORKLOAD_IMAGES.values(), MOCK_IDP_IMAGE):
            self._import_image(image)

    def _remove_mutable_cluster_images(self) -> None:
        """Prevent a recreated Pod from starting an obsolete mutable E2E image tag."""
        for image in (*WORKLOAD_IMAGES.values(), MOCK_IDP_IMAGE):
            self._run(
                (*self._k3s_command(), "ctr", "-n", "k8s.io", "images", "remove", image),
                allowed_codes={0, 1},
            )

    def _import_image(self, image: str) -> None:
        inspected = self._run(
            ("docker", "image", "inspect", image), allowed_codes={0, 1, 125}
        )
        if inspected.return_code != 0:
            cluster_images = set(
                self._run(
                    (*self._k3s_command(), "ctr", "-n", "k8s.io", "images", "list", "-q")
                ).output.splitlines()
            )
            if image in cluster_images:
                self.details.append(f"reuse k3s image: {image}")
                return
            if image.endswith(":e2e-local"):
                raise RuntimeError(
                    f"image is unavailable from both the local builder and k3s: {image}"
                )
            # k3s image GC can remove an unreferenced dependency between the
            # initial cache check and a later Helm install. Immutable external
            # images are safe to re-pull; mutable e2e-local images must have
            # been built explicitly and still fail closed above.
            self._run(("docker", "pull", image))
        with tempfile.NamedTemporaryFile(suffix=".tar") as archive:
            self._run(("docker", "save", "-o", archive.name, image))
            self._run(
                (
                    *self._k3s_command(),
                    "ctr",
                    "-n",
                    "k8s.io",
                    "images",
                    "import",
                    archive.name,
                )
            )

    def _install_envoy_gateway(self) -> None:
        chart_archives = sorted((self.helm_chart / "charts").glob("gateway-helm-*.tgz"))
        if not chart_archives:
            raise RuntimeError("Envoy Gateway dependency archive was not built")
        self._run(
            (
                "helm",
                "upgrade",
                "--install",
                self.envoy_release,
                str(chart_archives[-1]),
                "-n",
                self.namespace,
                "--set",
                f"global.images.envoyGateway.image={ALIYUN_ENVOY_GATEWAY_IMAGE}",
                "--set",
                "global.images.envoyGateway.pullPolicy=Never",
                "--set",
                f"global.images.envoyProxy.image={ALIYUN_ENVOY_IMAGE}",
                "--set",
                "global.images.envoyProxy.pullPolicy=Never",
                "--wait",
                f"--timeout={self.context.timeout_seconds}s",
            )
        )

    def _install_support_services(self) -> None:
        grpc_target = f"{self.authguard_release}.{self.namespace}.svc.cluster.local:8081"
        self._run(
            (
                "helm",
                "upgrade",
                "--install",
                self.support_release,
                str(self.support_chart),
                "-n",
                self.namespace,
                "--set-file",
                f"keycloak.realm={CONFIG_DIR / 'keycloak-realm.json'}",
                "--set-file",
                f"postgresql.initSQL={CONFIG_DIR / 'init.sql'}",
                "--set-file",
                f"keycloak.realmSigningPrivateKey={E2E_KEYS_DIR / 'realm-signing-key.pem'}",
                "--set-file",
                f"keycloak.realmSigningCertificate={E2E_KEYS_DIR / 'realm-signing-cert.pem'}",
                "--set-file",
                f"keycloak.realmSigningJwks={E2E_KEYS_DIR / 'realm-signing-jwk.json'}",
                "--set-file",
                f"keycloak.resignJwtPrivateKey={E2E_KEYS_DIR / 'resign-jwt-key.pem'}",
                "--set-file",
                f"keycloak.resignJwtPublicKey={E2E_KEYS_DIR / 'resign-jwt-key.pub.pem'}",
                "--set",
                f"authguard.grpcTarget={grpc_target}",
                "--set",
                f"gateway.name={self.gateway_name}",
            )
        )

    def _wait_for_support_services(self) -> None:
        """Wait until every support/workload Deployment has consumed its image."""
        for deployment in (
            self.keycloak_service,
            self.ldap_service,
            self.jaeger_service,
            self.postgresql_service,
            self.mock_idp_service,
            *[self.workload_service(component) for component in WORKLOAD_IMAGES],
        ):
            self._run(
                (
                    "kubectl",
                    "rollout",
                    "status",
                    f"deployment/{deployment}",
                    "-n",
                    self.namespace,
                    f"--timeout={self.context.timeout_seconds}s",
                )
            )

    def _install_authguard(self) -> None:
        values = self._authguard_values()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as values_file:
            json.dump(values, values_file)
            values_file.flush()
            self._run(
                (
                    "helm",
                    "upgrade",
                    "--install",
                    self.authguard_release,
                    str(self.helm_chart),
                    "-n",
                    self.namespace,
                    "-f",
                    values_file.name,
                    "--wait",
                    f"--timeout={self.context.timeout_seconds}s",
                )
            )

    def _authguard_values(self) -> dict:
        authguard_config = self._authguard_runtime_config()
        return {
            "envoy_gateway": {
                "enabled": False,
                "nameOverride": "envoy-gateway",
                "global": {
                    "images": {
                        "envoyProxy": {
                            "image": ALIYUN_ENVOY_IMAGE,
                            "pullPolicy": "Never",
                        }
                    }
                },
                "ext_authz": {
                    "enabled": True,
                    "gateway": {
                        "create": True,
                        "className": self.gateway_name,
                        "name": self.gateway_name,
                    },
                    "authguardRoute": {"enabled": False},
                    "authnRoute": {
                        "enabled": True,
                        "name": "e2e-authguard-customer-growth-authn",
                        "listenerPort": 8082,
                        "hostnames": [AUTHN_HOST],
                    },
                    "tracing": {
                        "enabled": True,
                        "backendRef": {"name": self.jaeger_service, "port": 4317},
                        "serviceName": "e2e-authguard-envoy-proxy",
                    },
                },
            },
            "redis_cluster": {
                "enabled": True,
                "nameOverride": "redis-cluster",
                "image": {
                    "registry": "registry.cn-shenzhen.aliyuncs.com",
                    "repository": "wl4g-k8s/bitnami_redis-cluster",
                    "tag": "7.0.14",
                    "pullPolicy": "Never",
                },
                "password": "e2e-authguard-redis-password",
                "cluster": {"nodes": 6, "replicas": 1},
                "persistence": {"enabled": False},
            },
            "fullnameOverride": self.authguard_release,
            "secrets": {
                # kubernetes provider: the support-chart Secret is injected
                # with envFrom, so all six credentials resolve natively.
                "provider": "kubernetes",
                "kubernetes": {"existingSecret": self.principal_discovery_secret},
            },
            "authguard": {
                "authn": {
                    "enabled": True,
                    "replicaCount": 1,
                    "image": {
                        "repository": AUTHGUARD_IMAGE.rsplit(":", 1)[0],
                        "tag": AUTHGUARD_IMAGE.rsplit(":", 1)[1],
                        "pullPolicy": "Never",
                    },
                    "disruptionBudget": {"enabled": False},
                    "canonical_jwt": {
                        "issuer": self.authn_issuer,
                        "audiences": ["customer-growth-job-service"],
                        "local_jwks": {
                            "existing_config_map": (
                                f"{self.support_release}-keycloak-realm-jwks"
                            ),
                            "inline": "",
                        },
                        "remote_jwks": {"uri": "", "backend_refs": []},
                    },
                },
                "authz": {
                    "replicaCount": 1,
                    "image": {
                        "repository": AUTHGUARD_IMAGE.rsplit(":", 1)[0],
                        "tag": AUTHGUARD_IMAGE.rsplit(":", 1)[1],
                        "pullPolicy": "Never",
                    },
                    "disruptionBudget": {"enabled": False},
                    "mgmt": {
                        "enabled": True,
                        "otelEnabled": True,
                        "otelEndpoint": (
                            f"http://{self.jaeger_service}.{self.namespace}"
                            ".svc.cluster.local:4317"
                        ),
                    },
                },
                # The COMPLETE main configuration (flowgent-chart style) is
                # rendered by Helm tpl into the authguard ConfigMap. Policy
                # data is deliberately absent: authorization policies are
                # imported into the Authguard storage as the post-deploy
                # bootstrap step (_bootstrap_authorization_policy).
                "authguard-config": authguard_config,
            },
        }

    def _authguard_runtime_config(self) -> str:
        """Full authguard.yaml main configuration for the E2E deployment."""
        keycloak_base = (
            f"http://{self.keycloak_service}.{self.namespace}.svc.cluster.local:8080"
        )
        jaeger_endpoint = (
            f"http://{self.jaeger_service}.{self.namespace}.svc.cluster.local:4317"
        )
        ldap_url = f"ldap://{self.ldap_service}.{self.namespace}.svc.cluster.local:389"
        mock_idp_url = (
            f"http://{self.mock_idp_service}.{self.namespace}.svc.cluster.local:8080"
        )
        redis_node = (
            f"redis://{self.authguard_release}-redis-cluster."
            f"{self.namespace}.svc.cluster.local:6379"
        )
        iam_postgres_url = (
            f"postgresql://{self.postgresql_service}.{self.namespace}.svc.cluster.local:5432/"
            "e2e_authguard_customer_growth?sslmode=disable&options=-csearch_path%3Dauthguard"
        )
        # ${KEY} references resolve from the Kubernetes envFrom-injected Secret.
        return "\n".join(
            [
                "authn:",
                "  providers:",
                "    github:",
                "      type: oauth2",
                "      issuer: https://github.com",
                "      clientId: e2e-authguard-github-client",
                '      clientSecret: "${AUTHGUARD_GITHUB_CLIENT_SECRET}"',
                f"      callbackUrl: http://{AUTHN_HOST}:8082/auth/v1/providers/github/callback",
                "      authorization:",
                f"        endpoint: {mock_idp_url + '/github/login/oauth/authorize'!r}",
                "        scopes: [read:user, user:email]",
                "      token:",
                f"        endpoint: {mock_idp_url + '/github/login/oauth/access_token'!r}",
                "        method: POST",
                "        headers:",
                "          accept: application/json",
                "      identity:",
                f"        endpoint: {mock_idp_url + '/github/user'!r}",
                "        subject: $.id",
                "        username: $.login",
                "        email: $.email",
                "    google:",
                "      type: oauth2",
                "      issuer: https://accounts.google.com",
                "      clientId: e2e-authguard-google-client",
                '      clientSecret: "${AUTHGUARD_GOOGLE_CLIENT_SECRET}"',
                f"      callbackUrl: http://{AUTHN_HOST}:8082/auth/v1/providers/google/callback",
                "      authorization:",
                f"        endpoint: {mock_idp_url + '/google/o/oauth2/v2/auth'!r}",
                "        scopes: [profile, email]",
                "      token:",
                f"        endpoint: {mock_idp_url + '/google/token'!r}",
                "        method: POST",
                "      identity:",
                f"        endpoint: {mock_idp_url + '/google/oauth2/v3/userinfo'!r}",
                "        subject: $.sub",
                "        username: $.name",
                "        email: $.email",
                "    e2e-authguard-keycloak:",
                "      type: oidc",
                f"      issuer: {keycloak_base + '/realms/example-corp'!r}",
                "      clientId: e2e-authguard-principal-discovery",
                '      clientSecret: "${AUTHGUARD_KEYCLOAK_CLIENT_SECRET}"',
                f"      callbackUrl: http://{AUTHN_HOST}:8082/auth/v1/providers/e2e-authguard-keycloak/callback",
                "      scopes: [openid, profile, email]",
                "      userinfo: true",
                "      tokenIntrospection:",
                f"        endpoint: {keycloak_base + '/realms/example-corp/protocol/openid-connect/token/introspect'!r}",
                "        acceptedAudiences: [customer-growth-job-service]",
                "      identity:",
                "        subject: $.sub",
                "        username: $.preferred_username",
                "        email: $.email",
                "        trustedClaims:",
                "          tenant_id: $.tenant_id",
                "    wechat:",
                "      type: oauth2-like",
                "      issuer: https://open.weixin.qq.com",
                "      clientId: e2e-authguard-wechat-app",
                '      clientSecret: "${AUTHGUARD_WECHAT_CLIENT_SECRET}"',
                f"      callbackUrl: http://{AUTHN_HOST}:8082/auth/v1/providers/wechat/callback",
                "      authorization:",
                f"        endpoint: {mock_idp_url + '/wechat/connect/qrconnect'!r}",
                "        scopes: [snsapi_login]",
                "      token:",
                f"        endpoint: {mock_idp_url + '/wechat/sns/oauth2/access_token'!r}",
                "        method: GET",
                "        clientCredentials: query",
                "        query:",
                "          appid: ${clientId}",
                "          secret: ${clientSecret}",
                "          code: ${authorizationCode}",
                "          grant_type: authorization_code",
                "      identity:",
                "        subject: $.unionid",
                "        fallbackSubject: $.openid",
                "    qq:",
                "      type: oauth2-like",
                "      issuer: https://graph.qq.com",
                "      clientId: e2e-authguard-qq-app",
                '      clientSecret: "${AUTHGUARD_QQ_CLIENT_SECRET}"',
                f"      callbackUrl: http://{AUTHN_HOST}:8082/auth/v1/providers/qq/callback",
                "      authorization:",
                f"        endpoint: {mock_idp_url + '/qq/oauth2.0/authorize'!r}",
                "        scopes: [get_user_info, get_vip_info]",
                "      token:",
                f"        endpoint: {mock_idp_url + '/qq/oauth2.0/token'!r}",
                "        method: GET",
                "        clientCredentials: query",
                "        query:",
                "          grant_type: authorization_code",
                "          client_id: ${clientId}",
                "          client_secret: ${clientSecret}",
                "          code: ${authorizationCode}",
                "          redirect_uri: ${redirectUri}",
                "          fmt: json",
                "      identity:",
                f"        endpoint: {mock_idp_url + '/qq/oauth2.0/me?fmt=json'!r}",
                "        subject: $.openid",
                "  accountLinking:",
                "    strategy: first-login",
                "    authoritativeProviders: []",
                "    allowLink: {}",
                "  session:",
                f"    issuer: {self.authn_issuer!r}",
                "    audience: customer-growth-job-service",
                "    ttl: 5m",
                "    stateTtl: 2m",
                '    privateKey: "${AUTHGUARD_AUTHN_SESSION_PRIVATE_KEY}"',
                "server:",
                "  service_name: authguard-authz",
                "  host: 0.0.0.0",
                "  port: 8080",
                "  scope_port: 8081",
                "  shutdown_timeout: 15s",
                "  request:",
                "    max_message_bytes: 1048576",
                "    timeout: 5s",
                "  response:",
                "    max_message_bytes: 1048576",
                "  performance:",
                "    worker_threads: 2",
                "    max_in_flight_requests: 4096",
                "mgmt:",
                "  enabled: true",
                "  host: 0.0.0.0",
                "  port: 9091",
                "  context_path: \"/\"",
                "  health:",
                "    liveness_path: \"/healthz\"",
                "    readiness_path: \"/readyz\"",
                "  metrics:",
                "    enabled: true",
                "    path: \"/metrics\"",
                "  otel:",
                "    enabled: true",
                f"    endpoint: {jaeger_endpoint!r}",
                "    protocol: grpc",
                "    timeout: 5s",
                "    sample_rate: 1.0",
                "logging:",
                "  mode: JSON",
                '  level: "info,tower_http=info"',
                "authz:",
                "  identity:",
                "    token_header: authorization",
                "    principal_id_claim: principal_id",
                "    principal_kind_claim: principal_kind",
                "    groups_claim: authguard_group_ids",
                "  scope_delivery:",
                "    direct_urn_limit: 1",
                "    max_direct_header_bytes: 8192",
                "    context_ttl: 30s",
                "    scope_token_ttl: 30s",
                "  principal_discovery:",
                "    keycloak:",
                "      - enabled: true",
                "        discovery_id: e2e-authguard-keycloak",
                f"        base_url: {keycloak_base!r}",
                "        realm: example-corp",
                f"        issuer: {self.issuer!r}",
                "        auth:",
                "          client_id: e2e-authguard-principal-discovery",
                '          client_secret: "${AUTHGUARD_KEYCLOAK_CLIENT_SECRET}"',
                "        connect_timeout: 3s",
                "        request_timeout: 10s",
                "        max_page_size: 100",
                "        allow_insecure_http: true",
                "    ldap:",
                "      - enabled: true",
                "        discovery_id: e2e-authguard-direct-ldap",
                f"        url: {ldap_url!r}",
                '        issuer: "urn:authguard:e2e:ldap:example-corp"',
                '        base_dn: "dc=example,dc=org"',
                "        auth:",
                '          bind_dn: "cn=svc-authguard,ou=Users,dc=example,dc=org"',
                '          bind_password: "${AUTHGUARD_LDAP_BIND_PASSWORD}"',
                "        user:",
                "          search_base: \"\"",
                '          object_filter: "(objectClass=posixAccount)"',
                "          id_attribute: uidNumber",
                "          name_attribute: cn",
                "          display_name_attribute: displayName",
                "          email_attribute: mail",
                "          search_attributes: [cn, displayName, mail, uidNumber]",
                "        group:",
                "          search_base: \"\"",
                '          object_filter: "(objectClass=posixGroup)"',
                "          id_attribute: gidNumber",
                "          name_attribute: ou",
                "          display_name_attribute: ou",
                "          search_attributes: [ou, gidNumber]",
                "        connect_timeout: 3s",
                "        request_timeout: 10s",
                "        max_page_size: 100",
                "        allow_insecure: true",
                "    scim:",
                "      enabled: true",
                "      discovery_id: e2e-authguard-keycloak",
                f"      issuer: {self.issuer!r}",
                "  resign:",
                "    enabled: true",
                "    max_ttl: 60s",
                '    private_key_b64: "${AUTHGUARD__AUTHZ__RESIGN__PRIVATE_KEY_B64}"',
                '  api_token: "${AUTHGUARD_SCIM_API_PASSWORD}"',
                "storage:",
                "  provider: Postgres",
                "  bootstrap_policy: null",
                "  sqlite:",
                '    url: "sqlite:///tmp/authguard.db"',
                "    max_connections: 1",
                "    connect_timeout: 5s",
                "  postgres:",
                f"    url: {iam_postgres_url!r}",
                "    username: e2e_authguard_service",
                '    password: "${AUTHGUARD__STORAGE__POSTGRES__PASSWORD}"',
                "    max_connections: 20",
                "    min_connections: 0",
                "    connect_timeout: 5s",
                "    idle_timeout: 10m",
                "    validate_on_acquire: true",
                "cache:",
                "  provider: Redis",
                "  memory:",
                "    initial_capacity: 32",
                "    max_capacity: 65535",
                "    ttl: 1h",
                "    eviction_policy: LRU",
                "  redis:",
                f"    nodes: [{redis_node!r}]",
                '    username: "default"',
                "    password: \"\"",
                "    key_prefix: authguard",
                "    connection_timeout: 3s",
                "    response_timeout: 6s",
                "    retries: 8",
                "    max_retry_wait: 65s",
                "    min_retry_wait: 1280ms",
                "    read_from_replica: false",
            ]
        )

    def _authorization_policy(
        self,
        *,
        revision: int,
        user_principal_ids: dict[str, str] | None = None,
    ) -> dict:
        route_specs = (
            ("job-list", "GET", "customer-growth.job.read", "/customer-growth/jobs"),
            ("job-read", "GET", "customer-growth.job.read", "/customer-growth/jobs/{id}"),
            ("job-create", "POST", "customer-growth.job.create", "/customer-growth/jobs"),
            ("job-update", "PUT", "customer-growth.job.update", "/customer-growth/jobs/{id}"),
            ("job-delete", "DELETE", "customer-growth.job.delete", "/customer-growth/jobs/{id}"),
        )
        routes_by_action: dict[str, list[dict]] = {}
        for route_id, method, action, path in route_specs:
            routes_by_action.setdefault(action, []).append(
                {
                    "id": route_id,
                    "methods": [method],
                    "hosts": list(WORKLOAD_HOSTS.values()),
                    "path": path,
                    "resource_urn": (
                        "urn:iam:prod:customer-growth:global:{tenant_id}:workspace/"
                        "customer-insights/project/retention-analytics"
                    ),
                    "parent_urns": [],
                }
            )
        action_ids = (
            "customer-growth.job.read",
            "customer-growth.job.create",
            "customer-growth.job.update",
            "customer-growth.job.delete",
        )
        policy = {
            "id": "default",
            "revision": revision,
            "name": "E2E customer growth authorization policy",
            "description": "Canonical Principal team access for five isolated workloads",
            "actions": [
                {
                    "identifier": action,
                    "description": f"Authorize {action.rsplit('.', 1)[-1]} operations",
                    "route_matchers": routes_by_action[action],
                }
                for action in action_ids
            ],
            "roles": [
                {
                    "id": "job.reader",
                    "name": "Customer growth job reader",
                    "description": "Read customer growth jobs within an assigned URN scope",
                    "action_ids": ["customer-growth.job.read"],
                },
                {
                    "id": "job.editor",
                    "name": "Customer growth job editor",
                    "description": "Create, read, update, and delete assigned jobs",
                    "action_ids": list(action_ids),
                },
            ],
            "role_bindings": [],
        }
        if user_principal_ids is None:
            return policy

        workspace = (
            "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights"
        )
        retention = f"{workspace}/project/retention-analytics"
        forecast = (
            f"{workspace}/project/lifetime-value-forecasting/job/"
            "daily-customer-lifetime-value-forecast"
        )
        policy["role_bindings"] = [
            {
                "id": "direct-reader-workspace",
                "principal_id": user_principal_ids["direct-reader"],
                "role_id": "job.reader",
                "effect": "ALLOW",
                "resource_urn": f"{workspace}/**",
                "conditions": {},
            },
            {
                "id": "token-editor-retention",
                "principal_id": user_principal_ids["token-editor"],
                "role_id": "job.editor",
                "effect": "ALLOW",
                "resource_urn": f"{retention}/**",
                "conditions": {},
            },
            {
                "id": "token-editor-forecast-read",
                "principal_id": user_principal_ids["token-editor"],
                "role_id": "job.reader",
                "effect": "ALLOW",
                "resource_urn": forecast,
                "conditions": {},
            },
            {
                "id": "token-editor-vip-deny",
                "principal_id": user_principal_ids["token-editor"],
                "role_id": "job.reader",
                "effect": "DENY",
                "resource_urn": f"{retention}/job/vip-retention-risk-audit",
                "conditions": {},
            },
            {
                "id": "growth-job-runner-read",
                "principal_id": "principal-growth-job-runner",
                "role_id": "job.reader",
                "effect": "ALLOW",
                "resource_urn": f"{retention}/**",
                "conditions": {},
            },
            {
                "id": "no-data-reader-function",
                "principal_id": user_principal_ids["no-data-reader"],
                "role_id": "job.reader",
                "effect": "ALLOW",
                "resource_urn": retention,
                "conditions": {},
            },
        ]
        return policy

    def _wait_for_resources(self) -> None:
        for deployment in (
            "envoy-gateway",
            self.keycloak_service,
            self.ldap_service,
            self.jaeger_service,
            self.postgresql_service,
            *[self.workload_service(component) for component in WORKLOAD_IMAGES],
            self.authguard_release,
            f"{self.authguard_release}-authn",
        ):
            self._run(
                (
                    "kubectl",
                    "rollout",
                    "status",
                    f"deployment/{deployment}",
                    "-n",
                    self.namespace,
                    f"--timeout={self.context.timeout_seconds}s",
                )
            )
        self._run(
            (
                "kubectl",
                "wait",
                "deployment",
                "-n",
                self.namespace,
                "-l",
                f"gateway.envoyproxy.io/owning-gateway-name={self.gateway_name}",
                "--for=condition=Available",
                f"--timeout={self.context.timeout_seconds}s",
            )
        )
        self._wait_for_gateway_api_acceptance()
        self._verify_identity_middleware_initialization()

    def _verify_identity_middleware_initialization(self) -> None:
        """Verify that enterprise directories and OAuth test IdPs initialized."""
        deployments = json.loads(
            self._run(
                (
                    "kubectl",
                    "get",
                    "deployment",
                    self.keycloak_service,
                    self.ldap_service,
                    self.mock_idp_service,
                    "-n",
                    self.namespace,
                    "-o",
                    "json",
                )
            ).output
        )["items"]
        by_name = {item["metadata"]["name"]: item for item in deployments}
        keycloak = by_name[self.keycloak_service]["spec"]["template"]["spec"]["containers"][0]
        keycloak_env = {item["name"] for item in keycloak.get("env", [])}
        if "--import-realm" not in keycloak.get("args", []) or not {
            "E2E_AUTHGUARD_PRINCIPAL_DISCOVERY_CLIENT_SECRET",
            "E2E_AUTHGUARD_WORKLOAD_CLIENT_SECRET",
        }.issubset(keycloak_env):
            raise RuntimeError("Keycloak realm/client bootstrap configuration is incomplete")

        ldap = by_name[self.ldap_service]["spec"]["template"]["spec"]
        ldap_container = ldap["containers"][0]
        secret_names = {
            volume.get("secret", {}).get("secretName") for volume in ldap.get("volumes", [])
        }
        if (
            not any(port.get("containerPort") == 389 for port in ldap_container.get("ports", []))
            or f"{self.support_release}-keycloak-credentials" not in secret_names
        ):
            raise RuntimeError("LDAP fixture/bind-secret bootstrap configuration is incomplete")

        mock_idp = by_name[self.mock_idp_service]["spec"]["template"]["spec"]["containers"][0]
        if not any(port.get("containerPort") == 8080 for port in mock_idp.get("ports", [])):
            raise RuntimeError("mock IdP OAuth2-like endpoints are not exposed")

        runtime = self._authguard_runtime_config()
        required = (
            f"base_url: 'http://{self.keycloak_service}",
            f"url: 'ldap://{self.ldap_service}",
            "discovery_id: e2e-authguard-keycloak",
            "discovery_id: e2e-authguard-direct-ldap",
            "${AUTHGUARD_KEYCLOAK_CLIENT_SECRET}",
            "${AUTHGUARD_LDAP_BIND_PASSWORD}",
            "${AUTHGUARD_GITHUB_CLIENT_SECRET}",
            "${AUTHGUARD_GOOGLE_CLIENT_SECRET}",
            "${AUTHGUARD_WECHAT_CLIENT_SECRET}",
            "${AUTHGUARD_QQ_CLIENT_SECRET}",
            "${AUTHGUARD__STORAGE__POSTGRES__PASSWORD}",
            "${AUTHGUARD_SCIM_API_PASSWORD}",
        )
        if missing := [value for value in required if value not in runtime]:
            raise RuntimeError(f"AuthZ discovery runtime configuration is incomplete: {missing}")

        with self._forward_service(self.keycloak_service, 8080) as port:
            with request.urlopen(
                f"http://127.0.0.1:{port}/realms/example-corp/.well-known/openid-configuration",
                timeout=15,
            ) as response:
                metadata = json.loads(response.read())
        if metadata.get("issuer") != self.issuer or not metadata.get("token_endpoint"):
            raise RuntimeError("Keycloak imported realm does not expose the expected OIDC metadata")
        with self._forward_service(self.mock_idp_service, 8080) as port:
            with request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=15) as response:
                mock_health = json.loads(response.read())
        if set(mock_health.get("providers", [])) != {"github", "google", "wechat", "qq"}:
            raise RuntimeError("mock IdP did not initialize all OAuth2-like provider endpoints")
        self._verify_secret_wiring()
        self.details.append(
            "Keycloak imported the deterministic realm/users/groups/clients; LDAP mounted its "
            "bind fixture; the mock IdP exposed GitHub/Google/WeChat/QQ contracts; AuthZ discovery "
            "references enterprise directories through Secret-backed credentials"
        )

    def _verify_secret_wiring(self) -> None:
        """Verify secret keys and references without reading any secret value."""
        template = '{{range $key, $_ := .data}}{{printf "%s\\n" $key}}{{end}}'
        keys = set(
            self._run(
                (
                    "kubectl",
                    "get",
                    "secret",
                    self.principal_discovery_secret,
                    "-n",
                    self.namespace,
                    "-o",
                    f"go-template={template}",
                )
            ).output.splitlines()
        )
        expected = {
            "AUTHGUARD__STORAGE__POSTGRES__PASSWORD",
            "AUTHGUARD_GITHUB_CLIENT_SECRET",
            "AUTHGUARD_GOOGLE_CLIENT_SECRET",
            "AUTHGUARD_WECHAT_CLIENT_SECRET",
            "AUTHGUARD_QQ_CLIENT_SECRET",
            "AUTHGUARD_KEYCLOAK_CLIENT_SECRET",
            "AUTHGUARD_LDAP_BIND_PASSWORD",
            "AUTHGUARD_SCIM_API_PASSWORD",
        }
        if missing := expected - keys:
            raise RuntimeError(f"external integration Secret lacks keys: {sorted(missing)}")
        redis_secret = f"{self.authguard_release}-redis-cluster"
        redis_keys = set(
            self._run(
                (
                    "kubectl",
                    "get",
                    "secret",
                    redis_secret,
                    "-n",
                    self.namespace,
                    "-o",
                    f"go-template={template}",
                )
            ).output.splitlines()
        )
        if "redis-password" not in redis_keys:
            raise RuntimeError("Redis Secret lacks redis-password")
        self.details.append(
            "verified key-only wiring for nine external credential classes: PostgreSQL, "
            "Redis, GitHub, Google, WeChat, QQ, Keycloak, LDAP, and SCIM; no value was read"
        )

    def _wait_for_gateway_api_acceptance(self) -> None:
        deadline = time.monotonic() + self.context.timeout_seconds
        expected_routes = {
            self.workload_service(component) for component in WORKLOAD_IMAGES
        }
        expected_routes.add("e2e-authguard-customer-growth-authn")
        last_state = "Gateway API status was not observed"
        while time.monotonic() < deadline:
            resources = json.loads(
                self._run(
                    (
                        "kubectl",
                        "get",
                        "gateway,httproute,securitypolicy",
                        "-n",
                        self.namespace,
                        "-o",
                        "json",
                    )
                ).output
            )["items"]
            gateway_accepted = False
            accepted_routes: set[str] = set()
            policy_accepted = False
            accepted_policy: dict | None = None
            for resource in resources:
                kind = resource["kind"]
                name = resource["metadata"]["name"]
                if kind == "Gateway" and name == self.gateway_name:
                    gateway_accepted = _has_true_condition(
                        resource.get("status", {}).get("conditions", []), "Accepted"
                    )
                elif kind == "HTTPRoute" and name in expected_routes:
                    parents = resource.get("status", {}).get("parents", [])
                    if any(
                        _has_true_condition(parent.get("conditions", []), "Accepted")
                        for parent in parents
                    ):
                        accepted_routes.add(name)
                elif kind == "SecurityPolicy" and name == self.authguard_release:
                    ancestors = resource.get("status", {}).get("ancestors", [])
                    policy_accepted = any(
                        _has_true_condition(
                            ancestor.get("conditions", []), "Accepted"
                        )
                        for ancestor in ancestors
                    )
                    accepted_policy = resource
            if (
                gateway_accepted
                and accepted_routes == expected_routes
                and policy_accepted
            ):
                if accepted_policy is None:
                    raise RuntimeError("accepted SecurityPolicy payload is unavailable")
                self._verify_security_policy_contract(accepted_policy)
                self.details.append(
                    "Gateway, five protected business routes, public AuthN route, and "
                    "listener-scoped SecurityPolicy are accepted"
                )
                return
            last_state = (
                f"gateway={gateway_accepted}, routes={len(accepted_routes)}/"
                f"{len(expected_routes)}, securityPolicy={policy_accepted}"
            )
            time.sleep(1)
        raise RuntimeError(f"Gateway API resources were not accepted: {last_state}")

    def _verify_security_policy_contract(self, policy: dict) -> None:
        spec = policy.get("spec", {})
        targets = spec.get("targetRefs", [])
        if not any(
            target.get("name") == self.gateway_name
            and target.get("sectionName") == "protected"
            for target in targets
        ):
            raise RuntimeError("SecurityPolicy must target only the protected listener")
        ext_auth = spec.get("extAuth", {})
        grpc = ext_auth.get("grpc", {})
        backends = grpc.get("backendRefs", [])
        expected_backend = {
            "name": self.authguard_release,
            "port": 8080,
        }
        if ext_auth.get("failOpen") is not False:
            raise RuntimeError("SecurityPolicy extAuth must fail closed")
        if not any(
            backend.get("name") == expected_backend["name"]
            and backend.get("port") == expected_backend["port"]
            for backend in backends
        ):
            raise RuntimeError(
                "SecurityPolicy extAuth does not target the Authguard Check gRPC port"
            )
        required_headers = {"authorization", "x-request-id", "traceparent", "tracestate"}
        configured_headers = set(ext_auth.get("headersToExtAuth", []))
        if not required_headers.issubset(configured_headers):
            missing = sorted(required_headers - configured_headers)
            raise RuntimeError(
                "SecurityPolicy does not forward required auth/trace headers to extAuth: "
                f"missing={missing}"
            )
        providers = spec.get("jwt", {}).get("providers", [])
        issuers = {provider.get("issuer") for provider in providers}
        if issuers != {self.authn_issuer}:
            raise RuntimeError("Envoy JWT policy must trust only the canonical AuthN issuer")

        jwt = spec.get("jwt", {})
        providers = jwt.get("providers", [])
        provider = next(
            (candidate for candidate in providers if candidate.get("issuer") == self.authn_issuer),
            None,
        )
        if jwt.get("optional") is not False or provider is None:
            raise RuntimeError("SecurityPolicy does not require the E2E AuthN issuer")
        if "customer-growth-job-service" not in provider.get("audiences", []):
            raise RuntimeError("SecurityPolicy does not validate the workload JWT audience")
        expected_jwks_config_map = f"{self.support_release}-keycloak-realm-jwks"
        local_jwks = provider.get("localJWKS", {})
        value_ref = local_jwks.get("valueRef", {})
        if "remoteJWKS" in provider:
            raise RuntimeError("SecurityPolicy unexpectedly loads remote JWKS")
        if (
            local_jwks.get("type") != "ValueRef"
            or value_ref.get("kind") != "ConfigMap"
            or value_ref.get("name") != expected_jwks_config_map
        ):
            raise RuntimeError(
                "SecurityPolicy does not load the deterministic realm JWKS from the "
                f"support ConfigMap {expected_jwks_config_map}"
            )
        jwks = json.loads(
            (E2E_KEYS_DIR / "realm-signing-jwk.json").read_text(encoding="utf-8")
        )
        if not isinstance(jwks.get("keys"), list) or not jwks["keys"]:
            raise RuntimeError("the deterministic Envoy local JWKS must contain keys")
        self.details.append(
            "SecurityPolicy requires only the AuthN issuer/audience and deterministic local "
            "JWKS, then calls fail-closed Authguard ext_auth gRPC on port 8080"
        )

    def _verify_jwt_gate_precedes_ext_auth(
        self,
        gateway_port: int,
        host: str,
        valid_token: str,
    ) -> None:
        with self._forward_envoy_admin() as envoy_admin_port:
            before_envoy = self._envoy_auth_counters(envoy_admin_port)
            before_check = self._authorization_check_count()
            status, _ = self._http(
                gateway_port,
                host,
                "/customer-growth/jobs",
                headers={"Authorization": f"Bearer {self._tamper_jwt_signature(valid_token)}"},
            )
            self._expect_status("tampered AuthN JWT rejected by Envoy", status, 401)
            after_invalid_envoy = self._envoy_auth_counters(envoy_admin_port)
            after_invalid_check = self._authorization_check_count()
            if after_invalid_check != before_check:
                raise RuntimeError(
                    "tampered JWT reached Authguard Check; Envoy JWT verification did not run first"
                )
            self._expect_counter_delta(
                "tampered JWT Envoy jwt_authn.denied",
                before_envoy,
                after_invalid_envoy,
                "jwt_denied",
                1,
            )
            for counter in ("ext_auth_ok", "ext_auth_denied", "ext_auth_error"):
                self._expect_counter_delta(
                    f"tampered JWT Envoy {counter}",
                    before_envoy,
                    after_invalid_envoy,
                    counter,
                    0,
                )

            status, _ = self._http(
                gateway_port,
                host,
                "/customer-growth/jobs",
                headers={"Authorization": f"Bearer {valid_token}"},
            )
            self._expect_status("valid AuthN JWT passed Envoy and ext_auth", status, 200)
            after_valid_envoy = self._envoy_auth_counters(envoy_admin_port)
            after_valid_check = self._authorization_check_count()
            if after_valid_check != after_invalid_check + 1:
                raise RuntimeError(
                    "valid JWT did not produce exactly one Authguard Authorization/Check call: "
                    f"before={after_invalid_check}, after={after_valid_check}"
                )
            self._expect_counter_delta(
                "valid JWT Envoy jwt_authn.allowed",
                after_invalid_envoy,
                after_valid_envoy,
                "jwt_allowed",
                1,
            )
            self._expect_counter_delta(
                "valid JWT Envoy ext_authz.ok",
                after_invalid_envoy,
                after_valid_envoy,
                "ext_auth_ok",
                1,
            )
            for counter in ("ext_auth_denied", "ext_auth_error"):
                self._expect_counter_delta(
                    f"valid JWT Envoy {counter}",
                    after_invalid_envoy,
                    after_valid_envoy,
                    counter,
                    0,
                )
        self.details.append(
            "tampered JWT caused zero Authguard Check calls; valid AuthN JWT caused "
            "exactly one envoy.service.auth.v3.Authorization/Check call"
        )

    def _verify_workload_client_credentials(
        self, gateway_port: int, authn_gateway_port: int
    ) -> None:
        """Prove the machine-identity flow: a business SA exchanges its own
        client secret for an access token (OAuth2 client_credentials — no
        browser, no user login) and the audience mapper stamps the workload
        audience so Envoy accepts it."""
        with self._forward_service(self.keycloak_service, 8080) as keycloak_port:
            exchange = parse.urlencode(
                {
                    "grant_type": "client_credentials",
                    "client_id": "e2e-authguard-growth-job-runner",
                    "client_secret": "e2e-authguard-workload-client-secret",
                    "audience": "customer-growth-job-service",
                }
            ).encode()
            token_request = request.Request(
                f"http://127.0.0.1:{keycloak_port}"
                "/realms/example-corp/protocol/openid-connect/token",
                data=exchange,
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            with request.urlopen(token_request, timeout=15) as response:
                workload_external_token = json.loads(response.read())["access_token"]
        workload_token = self._canonicalize_token(
            authn_gateway_port, workload_external_token, "WORKLOAD"
        )
        claims = self._jwt_claims(workload_token)
        audience = claims.get("aud")
        audiences = {audience} if isinstance(audience, str) else set(audience or [])
        if "customer-growth-job-service" not in audiences:
            raise RuntimeError(
                "workload client_credentials token lacks the customer-growth-job-service "
                f"audience: {audience!r}"
            )
        if claims.get("principal_id") != "principal-growth-job-runner":
            raise RuntimeError("workload token lacks its canonical principal_id claim")
        if claims.get("principal_kind") != "WORKLOAD":
            raise RuntimeError("workload token lacks the WORKLOAD principal_kind claim")
        if claims.get("tenant_id") != "example-corp":
            raise RuntimeError("workload token lacks its trusted tenant_id claim")
        forbidden = {
            "id": 103,
            "region": "global",
            "tenant_id": "example-corp",
            "workspace_id": "customer-insights",
            "project_id": "retention-analytics",
            "job_id": "workload-forbidden-create",
            "display_name": "Must not be created",
            "status": "READY",
            "owner_user_id": "growth-job-runner",
        }
        for component, host in WORKLOAD_HOSTS.items():
            status, body = self._http(
                gateway_port,
                host,
                "/customer-growth/jobs",
                headers={"Authorization": f"Bearer {workload_token}"},
            )
            self._expect_status(f"{component}: workload read action", status, 200)
            self._expect_job_ids(f"{component}: workload data scope", body, [1, 2, 6])
            status, _ = self._http(
                gateway_port,
                host,
                "/customer-growth/jobs",
                method="POST",
                headers={"Authorization": f"Bearer {workload_token}"},
                json_body=forbidden,
            )
            self._expect_status(
                f"{component}: workload without create action is rejected by AuthZ",
                status,
                403,
            )
        self.details.append(
            "pre-authorized biz SA client_credentials token entered AuthN token exchange, "
            "then all five services enforced its read scope and AuthZ denied create"
        )

    def _canonicalize_token(
        self,
        authn_gateway_port: int,
        external_token: str,
        kind: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> str:
        payload = json.dumps(
            {"subjectToken": external_token, "kind": kind}, separators=(",", ":")
        ).encode()
        exchange = request.Request(
            f"http://127.0.0.1:{authn_gateway_port}"
            "/auth/v1/providers/e2e-authguard-keycloak/token-exchange",
            data=payload,
            method="POST",
            headers={
                "Host": AUTHN_HOST,
                "Content-Type": "application/json",
                **(headers or {}),
            },
        )
        with request.urlopen(exchange, timeout=20) as response:
            login = json.loads(response.read())
        token = login.get("accessToken", "")
        claims = self._jwt_claims(token)
        if claims.get("iss") != self.authn_issuer or claims.get("principal_kind") != kind:
            raise RuntimeError("OIDC token exchange did not return a canonical AuthN token")
        return token

    def _verify_resign_token_boundary(self, gateway_port: int, direct_token: str) -> None:
        """Prove the Authguard-origin boundary on the rust workload.

        Authguard re-signs every allowed request with authguardOrigin: true;
        the rust-sqlx service mounts the paired public key and rejects any
        Authorization header without that signature. A valid user JWT through
        Envoy is re-signed on ALLOW, so the request succeeds and the workload
        logs the verification; the same JWT sent directly to the workload
        (bypassing Envoy) fails the proof boundary with HTTP 401.
        """
        host = WORKLOAD_HOSTS["rust-sqlx"]
        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs",
            headers={"Authorization": f"Bearer {direct_token}"},
        )
        self._expect_status(
            "rust workload accepts the Authguard resign JWT through Envoy", status, 200
        )

        with self._forward_service(self.workload_service("rust-sqlx"), 8080) as workload_port:
            status, body = self._http(
                workload_port,
                host,
                "/customer-growth/jobs",
                headers={"Authorization": f"Bearer {direct_token}"},
            )
            self._expect_status(
                "direct client call without a resign JWT is rejected", status, 401
            )
            if "resign JWT" not in body:
                raise RuntimeError(
                    "direct-call rejection does not identify the resign proof boundary: "
                    f"{body!r}"
                )

        logs = self._run(
            (
                "kubectl",
                "logs",
                "-n",
                self.namespace,
                f"deployment/{self.workload_service('rust-sqlx')}",
                "--tail=200",
            )
        ).output
        if "verified Authguard resign JWT" not in logs:
            raise RuntimeError("rust workload never verified an Authguard resign JWT")
        self.details.append(
            "rust workload verified the re-signed Authguard-origin JWT through Envoy and "
            "rejected a direct client call carrying the unmodified AuthN token"
        )

    @staticmethod
    def _tamper_jwt_signature(token: str) -> str:
        parts = token.split(".")
        if len(parts) != 3 or not parts[2]:
            raise RuntimeError("identity issuer returned a malformed signed JWT")
        replacement = "A" if parts[2][0] != "A" else "B"
        parts[2] = replacement + parts[2][1:]
        return ".".join(parts)

    def _authorization_check_count(self) -> int:
        with self._forward_service(self.authguard_release, 9091) as port:
            with request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=15) as response:
                metrics = response.read().decode()
        total = 0
        for line in metrics.splitlines():
            if not line.startswith("authguard_http_requests_total{"):
                continue
            if 'route="envoy.service.auth.v3.Authorization/Check"' not in line:
                continue
            if 'method="gRPC"' not in line:
                continue
            total += int(float(line.rsplit(maxsplit=1)[1]))
        return total

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

    @staticmethod
    def _expect_counter_delta(
        label: str,
        before: dict[str, int],
        after: dict[str, int],
        counter: str,
        expected: int,
    ) -> None:
        actual = after[counter] - before[counter]
        if actual != expected:
            raise RuntimeError(f"{label}: expected delta {expected}, got {actual}")

    @staticmethod
    def _envoy_auth_counters(port: int) -> dict[str, int]:
        with request.urlopen(
            f"http://127.0.0.1:{port}/stats?filter=(jwt_authn|ext_authz)&format=json",
            timeout=15,
        ) as response:
            stats = json.loads(response.read()).get("stats", [])
        suffixes = {
            "jwt_allowed": ".jwt_authn.allowed",
            "jwt_denied": ".jwt_authn.denied",
            "ext_auth_ok": ".ext_authz.ok",
            "ext_auth_denied": ".ext_authz.denied",
            "ext_auth_error": ".ext_authz.error",
        }
        counters = {name: 0 for name in suffixes}
        for stat in stats:
            metric = stat.get("name", "")
            if not metric.startswith("http."):
                continue
            for name, suffix in suffixes.items():
                if metric.endswith(suffix):
                    counters[name] += int(stat.get("value", 0))
        return counters

    def _authorization_denied_reasons(self) -> dict[str, int]:
        """Per-reason denial counts from the Authguard decisions metric."""
        with self._forward_service(self.authguard_release, 9091) as port:
            with request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=15) as response:
                metrics = response.read().decode()
        reasons: dict[str, int] = {}
        for line in metrics.splitlines():
            metric = 'authguard_authorization_decisions_total{decision="deny"'
            if not line.startswith(metric):
                continue
            label = line[len(metric):].split("}", 1)[0]
            reasons.setdefault(label, 0)
            reasons[label] += int(line.rsplit(" ", 1)[1])
        return reasons

    def _password_token(
        self,
        port: int,
        username: str,
        password: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> str:
        payload = parse.urlencode(
            {
                "grant_type": "password",
                "client_id": "customer-growth-job-service",
                "username": username,
                "password": password,
                "scope": "openid profile email",
            }
        ).encode()
        token_request = request.Request(
            f"http://127.0.0.1:{port}/realms/example-corp/protocol/openid-connect/token",
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                **(headers or {}),
            },
        )
        with request.urlopen(token_request, timeout=15) as response:
            return json.loads(response.read())["access_token"]

    def _verify_distributed_trace(
        self, gateway_port: int, component: str, host: str, canonical_token: str
    ) -> None:
        trace = E2ETrace(f"customer-growth.authorization.{component}.e2e")
        gateway_span = trace.start_client(
            "envoy.customer_growth_jobs",
            **{
                "server.address": host,
                "http.request.method": "GET",
                "url.path": "/customer-growth/jobs",
            },
        )
        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs",
            headers={
                "Authorization": f"Bearer {canonical_token}",
                "traceparent": gateway_span.traceparent,
                "x-request-id": trace.request_id,
            },
        )
        gateway_span.finish()
        self._expect_status("OTel-correlated authorized request", status, 200)

        self._export_verifier_trace(trace)

        with self._forward_service(self.jaeger_service, 16686) as query_port:
            verifier = AuthorizationJaegerTraceVerifier(
                workload_service=f"e2e-authguard-{component}"
            )
            payload = self._jaeger_query(query_port).wait_for_trace(trace, verifier)
        verifier.verify(payload, trace)
        self.details.extend(
            [
                f"{component}: Jaeger verified verifier -> Envoy -> AuthZ and "
                "Envoy -> Biz causal branches",
                f"{component} Jaeger trace ID: {trace.trace_id}",
                (
                    "Jaeger UI: kubectl -n "
                    f"{self.namespace} port-forward service/{self.jaeger_service} "
                    "16686:16686, then open "
                    f"http://127.0.0.1:16686/trace/{trace.trace_id}"
                ),
            ]
        )

    def _verify_authn_distributed_traces(self) -> None:
        expected_providers = tuple(
            flow["provider_id"] for flow in self.authn_scenarios["provider_flows"]
        )
        missing = set(expected_providers) - self.authn_traces.keys()
        if missing:
            raise RuntimeError(f"AuthN trace producers are missing for {sorted(missing)}")
        for provider in expected_providers:
            self._export_verifier_trace(self.authn_traces[provider])

        with self._forward_service(self.jaeger_service, 16686) as query_port:
            jaeger = self._jaeger_query(query_port)
            trace_ids: list[str] = []
            for provider in expected_providers:
                trace = self.authn_traces[provider]
                verifier = AuthnJaegerTraceVerifier(
                    provider=provider,
                    principal_id=self.authn_trace_principals[provider],
                )
                payload = jaeger.wait_for_trace(trace, verifier)
                verifier.verify(payload, trace)
                trace_ids.append(trace.trace_id)
            jaeger.require_services({"authguard-authn"})
        self.details.append(
            "Jaeger Query API verified AuthN authorize/callback server spans and "
            "provider child spans for " + ", ".join(expected_providers)
        )
        self.details.append("AuthN Jaeger trace IDs: " + ", ".join(trace_ids))

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

    def _verify_route_matcher_denials(self) -> None:
        """The access-condition step must deny before any scope machinery runs."""
        denied = self._authorization_denied_reasons()
        route_denials = sum(
            count
            for label, count in denied.items()
            if "route_not_mapped" in label
        )
        if route_denials < len(WORKLOAD_HOSTS):
            raise RuntimeError(
                "route matcher denials are missing: expected one route_not_mapped "
                "denial per workload for the unmapped-path probes"
            )
        self.details.append(
            f"{route_denials} route_not_mapped authorization denials observed: "
            "the access-condition route matcher rejected unmapped HTTP tuples "
            "before any resign/scope delivery"
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

    def _verify_redis_cluster(self) -> None:
        result = self._run(
            (
                "kubectl",
                "get",
                "pods",
                "-n",
                self.namespace,
                "-l",
                "app.kubernetes.io/name=redis-cluster",
                "-o",
                "jsonpath={.items[0].metadata.name}",
            )
        )
        pod = result.output.strip()
        cluster = self._run(
            (
                "kubectl",
                "exec",
                "-n",
                self.namespace,
                pod,
                "--",
                "bash",
                "-lc",
                'REDISCLI_AUTH="$REDIS_PASSWORD" '
                "/opt/bitnami/redis/bin/redis-cli cluster info",
            )
        )
        if "cluster_state:ok" not in cluster.output:
            raise RuntimeError("Redis Cluster is not healthy")
        self.details.append("Redis Cluster reports all slots covered")

    def _verify_postgresql_schema_isolation(self) -> None:
        pod = self._run(
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
        isolation = self._run(
            (
                "kubectl",
                "exec",
                "-n",
                self.namespace,
                pod,
                "--",
                "bash",
                "-ec",
                f'PGPASSWORD="$POSTGRESQL_POSTGRES_PASSWORD" psql -U postgres -d "$POSTGRESQL_DATABASE" -Atc "{sql}"',
            )
        ).output.strip()
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

    def _verify_running_images(self) -> None:
        result = self._run(
            (
                "kubectl",
                "get",
                "pods",
                "-n",
                self.namespace,
                "-o",
                "json",
            )
        )
        pod_list = json.loads(result.output)
        images = {
            container["image"]
            for pod in pod_list["items"]
            for container in (
                pod["spec"].get("initContainers", [])
                + pod["spec"].get("containers", [])
                + pod["spec"].get("ephemeralContainers", [])
            )
        }
        expected = {
            ALIYUN_ENVOY_IMAGE,
            ALIYUN_ENVOY_GATEWAY_IMAGE,
            ALIYUN_REDIS_IMAGE,
            ALIYUN_KEYCLOAK_IMAGE,
            ALIYUN_LDAP_IMAGE,
            ALIYUN_JAEGER_IMAGE,
            ALIYUN_POSTGRES_IMAGE,
            AUTHGUARD_IMAGE,
            *WORKLOAD_IMAGES.values(),
        }
        missing = expected - images
        if missing:
            raise RuntimeError(f"expected Aliyun images are not running: {sorted(missing)}")
        non_aliyun = sorted(
            image
            for image in images
            if not image.startswith("registry.cn-shenzhen.aliyuncs.com/")
        )
        if non_aliyun:
            raise RuntimeError(f"non-Aliyun runtime images detected: {non_aliyun}")
        self.details.append("all running images use registry.cn-shenzhen.aliyuncs.com")

    def _verify_zero_container_restarts(self) -> None:
        result = self._run(
            (
                "kubectl",
                "get",
                "pods",
                "-n",
                self.namespace,
                "-o",
                "json",
            )
        )
        restarted: list[str] = []
        for pod in json.loads(result.output)["items"]:
            statuses = pod.get("status", {}).get("initContainerStatuses", []) + pod.get(
                "status", {}
            ).get("containerStatuses", [])
            restart_count = sum(status.get("restartCount", 0) for status in statuses)
            if restart_count:
                restarted.append(f"{pod['metadata']['name']}={restart_count}")
        if restarted:
            raise RuntimeError(
                "containers restarted during clean E2E deployment: " + ", ".join(restarted)
            )
        self.details.append("all E2E containers remained at zero restarts")

    def _envoy_proxy_service(self) -> str:
        result = self._run(
            (
                "kubectl",
                "get",
                "services",
                "-n",
                self.namespace,
                "-l",
                f"gateway.envoyproxy.io/owning-gateway-name={self.gateway_name}",
                "-o",
                "jsonpath={.items[0].metadata.name}",
            )
        )
        service = result.output.strip()
        if not service:
            raise RuntimeError("Envoy Proxy service was not created")
        return service

    @contextmanager
    def _forward_envoy_admin(self) -> Iterator[int]:
        payload = json.loads(
            self._run(
                (
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    self.namespace,
                    "-l",
                    f"gateway.envoyproxy.io/owning-gateway-name={self.gateway_name}",
                    "-o",
                    "json",
                )
            ).output
        )
        ready = [
            item
            for item in payload.get("items", [])
            if item.get("status", {}).get("phase") == "Running"
            and any(
                condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in item.get("status", {}).get("conditions", [])
            )
        ]
        if not ready:
            raise RuntimeError("no ready Envoy Proxy pod was created")
        pod = max(
            ready,
            key=lambda item: item.get("metadata", {}).get("creationTimestamp", ""),
        ).get("metadata", {}).get("name", "")
        if not pod:
            raise RuntimeError("ready Envoy Proxy pod has no name")
        with self._forward_resource(f"pod/{pod}", 19000) as port:
            yield port

    @contextmanager
    def _forward_service(self, service: str, remote_port: int) -> Iterator[int]:
        with self._forward_resource(f"service/{service}", remote_port) as port:
            yield port

    @contextmanager
    def _forward_resource(self, resource: str, remote_port: int) -> Iterator[int]:
        local_port = _free_port()
        process = subprocess.Popen(
            (
                "kubectl",
                "port-forward",
                "--address=127.0.0.1",
                "-n",
                self.namespace,
                resource,
                f"{local_port}:{remote_port}",
            ),
            cwd=PROJECT_ROOT,
            env={**os.environ, **self.environment},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_for_port(process, local_port)
            yield local_port
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def _k3s_command(self) -> tuple[str, ...]:
        configured = os.getenv("AUTHGUARD_E2E_K3S_COMMAND")
        if configured:
            return tuple(shlex.split(configured))
        if os.geteuid() == 0 and shutil.which("k3s"):
            return ("k3s",)
        if shutil.which("sudo") and shutil.which("k3s"):
            return ("sudo", "-n", "k3s")
        raise RuntimeError(
            "k3s image import is unavailable; set AUTHGUARD_E2E_K3S_COMMAND"
        )

    def _run(
        self,
        command: tuple[str, ...],
        *,
        cwd: Path = PROJECT_ROOT,
        allowed_codes: set[int] | None = None,
    ) -> CommandResult:
        result = run_command(
            command,
            cwd=cwd,
            environment=self.environment,
            timeout_seconds=self.context.timeout_seconds,
        )
        self.commands.append(result)
        allowed = allowed_codes or {0}
        if result.return_code not in allowed:
            tail = "\n".join(result.output.splitlines()[-40:])
            raise RuntimeError(
                f"command failed ({result.return_code}): {' '.join(command)}\n{tail}"
            )
        return result


def _free_port() -> int:
    for port in LOCAL_PORT_RANGE:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            try:
                listener.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no free E2E host port remains in 28800-28899")


def _has_true_condition(conditions: list[dict], condition_type: str) -> bool:
    return any(
        condition.get("type") == condition_type
        and condition.get("status") == "True"
        for condition in conditions
    )


def _wait_for_port(process: subprocess.Popen, port: int) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("kubectl port-forward exited before becoming ready")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("timed out waiting for kubectl port-forward")
