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
from .telemetry import E2ETrace, JaegerTraceVerifier


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
AUTHGUARD_ADMIN_TOKEN = "e2e-admin-token"
E2E_ACCESS_CONTEXT_SECRET = "e2e-customer-growth-support-e2e-authguard-access-context"
WORKLOAD_IMAGES = {
    "go-sqlx": "registry.cn-shenzhen.aliyuncs.com/wl4g/e2e-customer-growth-go-sqlx:e2e-local",
    "rust-sqlx": "registry.cn-shenzhen.aliyuncs.com/wl4g/e2e-customer-growth-rust-sqlx:e2e-local",
    "python-sqlalchemy": "registry.cn-shenzhen.aliyuncs.com/wl4g/e2e-customer-growth-python-sqlalchemy:e2e-local",
    "spring-jdbc": "registry.cn-shenzhen.aliyuncs.com/wl4g/e2e-customer-growth-spring-jdbc:e2e-local",
    "spring-jpa": "registry.cn-shenzhen.aliyuncs.com/wl4g/e2e-customer-growth-spring-jpa:e2e-local",
}
WORKLOAD_DIRECTORIES = {
    "go-sqlx": "golang-sqlx-service",
    "rust-sqlx": "rust-sqlx-service",
    "python-sqlalchemy": "python-sqlalchemy-service",
    "spring-jdbc": "springboot-jdbc-service",
    "spring-jpa": "springboot-jpa-service",
}
WORKLOAD_HOSTS = {
    component: f"e2e-{component}.customer-growth.local" for component in WORKLOAD_IMAGES
}
GROUP_EXTERNAL_IDS = {
    "direct-readers": "group:11111111-1111-4111-8111-111111111111",
    "token-editors": "group:22222222-2222-4222-8222-222222222222",
}


class KubernetesE2E:
    """Own one disposable namespace and the three Helm releases inside it."""

    def __init__(self, context: RunContext) -> None:
        self.context = context
        self.namespace = os.getenv("AUTHGUARD_E2E_NAMESPACE", "e2e-customer-growth")
        self.release = os.getenv("AUTHGUARD_E2E_RELEASE", "e2e-customer-growth")
        if not self.namespace.startswith("e2e-"):
            raise ValueError("AUTHGUARD_E2E_NAMESPACE must start with e2e-")
        if not self.release.startswith("e2e-"):
            raise ValueError("AUTHGUARD_E2E_RELEASE must start with e2e-")
        self.envoy_release = f"{self.release}-envoy"
        self.support_release = f"{self.release}-support"
        self.authguard_release = f"{self.release}-authguard"
        self.gateway_name = "e2e-customer-growth-gateway"
        self.environment = {
            "KUBECONFIG": os.getenv(
                "KUBECONFIG", str(Path.home() / ".kube" / "config")
            )
        }
        self.commands: list[CommandResult] = []
        self.details: list[str] = []
        self.helm_chart = PROJECT_ROOT / "deploy" / "helm" / "authguard"
        self.support_chart = E2E_DIR / "kubernetes"
        self.deploy_dir = E2E_DIR / "deploy"
        self.principal_scenarios = json.loads(
            (CONFIG_DIR / "principal-discovery-scenarios.json").read_text(
                encoding="utf-8"
            )
        )
        if self.principal_scenarios.get("version") != 1:
            raise ValueError("principal discovery fixture version must be 1")

    @property
    def keycloak_service(self) -> str:
        return f"{self.support_release}-e2e-keycloak"

    @property
    def postgresql_service(self) -> str:
        return f"{self.support_release}-e2e-postgresql"

    @property
    def jaeger_service(self) -> str:
        return f"{self.support_release}-e2e-jaeger"

    @property
    def ldap_service(self) -> str:
        return f"{self.support_release}-e2e-ldap"

    @property
    def principal_discovery_secret(self) -> str:
        return f"{self.support_release}-e2e-principal-discovery-credentials"

    def workload_service(self, component: str) -> str:
        return f"{self.support_release}-e2e-{component}"

    @property
    def issuer(self) -> str:
        return (
            f"http://{self.keycloak_service}.{self.namespace}.svc.cluster.local:8080"
            "/realms/example-corp"
        )

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
        self._prepare_workload_images()
        self._install_support_services()
        self._import_image(AUTHGUARD_IMAGE)
        # Redis is installed by the Authguard chart with pullPolicy=Never. Import it
        # immediately before Helm creates the StatefulSet so k3s image GC cannot
        # collect an unreferenced image while the support services are starting.
        self._import_image(ALIYUN_REDIS_IMAGE)
        self._install_authguard()
        self._wait_for_resources()

    def verify_scenarios(self) -> None:
        self._verify_envoy_runtime_filter_chain()
        with self._forward_service(self.keycloak_service, 8080) as keycloak_port:
            direct_token = self._password_token(
                keycloak_port, "direct-reader", "direct-reader-password"
            )
            editor_token = self._password_token(
                keycloak_port, "token-editor", "token-editor-password"
            )
            self._expect_token_claims(direct_token, "direct-readers")
            self._expect_token_claims(editor_token, "token-editors")

        envoy_service = self._envoy_proxy_service()
        with self._forward_service(envoy_service, 80) as gateway_port:
            self._bootstrap_authorization_policy(
                gateway_port, direct_token, editor_token
            )
            self._verify_jwt_gate_precedes_ext_auth(
                gateway_port,
                next(iter(WORKLOAD_HOSTS.values())),
                direct_token,
            )
            self._verify_distributed_trace(
                gateway_port,
                next(iter(WORKLOAD_HOSTS.values())),
            )
            for component, host in WORKLOAD_HOSTS.items():
                self._verify_workload_contract(
                    gateway_port, component, host, direct_token, editor_token
                )

        self._verify_metrics()
        self._verify_authguard_check_logs()
        self._verify_redis_cluster()
        self._verify_postgresql_schema_isolation()
        self._verify_running_images()
        self._verify_zero_container_restarts()

    def _bootstrap_authorization_policy(
        self,
        gateway_port: int,
        direct_token: str,
        editor_token: str,
    ) -> None:
        """Project trusted principals before atomically binding the policy."""
        bootstrap_host = next(iter(WORKLOAD_HOSTS.values()))
        with self._forward_service("e2e-customer-growth-authguard", 9091) as port:
            jit_principals = self._verify_jit_principal_discovery(
                port,
                gateway_port,
                bootstrap_host,
                {
                    "direct-reader": direct_token,
                    "token-editor": editor_token,
                },
            )
            self._verify_federated_principal_discovery(port)
            self._verify_scim_principal_discovery(port, jit_principals)
            group_principal_ids = self._required_group_principal_ids(port)

            status, body = self._admin_http(port, "/adm/v1/policy")
            self._expect_status("read bootstrap policy", status, 200)
            revision = json.loads(body)["revision"]
            replacement = self._authorization_policy(
                revision=revision,
                group_principal_ids=group_principal_ids,
            )
            status, body = self._admin_http(
                port,
                "/adm/v1/policy",
                method="PUT",
                headers={"If-Match": str(revision)},
                json_body=replacement,
            )
            self._expect_status("bind projected principals atomically", status, 200)
            persisted = json.loads(body)
            if persisted.get("revision", 0) <= revision:
                raise RuntimeError("policy replacement did not advance its revision")
            self.details.append(
                "JIT group principals were bound by one revision-checked policy replacement"
            )

    def _verify_jit_principal_discovery(
        self,
        admin_port: int,
        gateway_port: int,
        host: str,
        tokens: dict[str, str],
    ) -> dict[str, dict[str, dict]]:
        """Prove repeated trusted OIDC requests converge on stable projections."""
        resolved: dict[str, dict[str, dict]] = {"users": {}, "groups": {}}
        expected_users = self.principal_scenarios["jit"]["users"]
        for expected in expected_users:
            username = expected["username"]
            token = tokens.get(username)
            if not token:
                raise RuntimeError(f"JIT fixture has no token for {username!r}")
            subject = self._required_string_claim(token, "sub")
            stable_user_id: str | None = None
            stable_group_ids: dict[str, str] = {}
            for attempt in (1, 2):
                status, _ = self._http(
                    gateway_port,
                    host,
                    "/customer-growth/jobs",
                    headers={"Authorization": f"Bearer {token}"},
                )
                if status not in {200, 403}:
                    raise RuntimeError(
                        f"{username}: JIT request {attempt} expected HTTP 403 or 200, "
                        f"got {status}"
                    )
                principal = self._expect_single_principal(
                    admin_port,
                    issuer=self.issuer,
                    external_id=subject,
                    expected_kind=expected["expected_kind"],
                )
                if stable_user_id is not None and principal["id"] != stable_user_id:
                    raise RuntimeError(
                        f"{username}: repeated JIT projection changed its local identifier"
                    )
                stable_user_id = principal["id"]
                resolved["users"][username] = principal

                for group in expected["groups"]:
                    external_id = GROUP_EXTERNAL_IDS.get(group)
                    if external_id is None:
                        raise RuntimeError(f"JIT fixture references unknown group {group!r}")
                    group_principal = self._expect_single_principal(
                        admin_port,
                        issuer=self.issuer,
                        external_id=external_id,
                        expected_kind="GROUP",
                    )
                    previous_id = stable_group_ids.get(group)
                    if previous_id is not None and group_principal["id"] != previous_id:
                        raise RuntimeError(
                            f"{group}: repeated JIT projection changed its local identifier"
                        )
                    stable_group_ids[group] = group_principal["id"]
                    resolved["groups"][group] = group_principal

        self.details.append(
            "OIDC JIT discovery idempotently projected "
            f"{len(resolved['users'])} users and {len(resolved['groups'])} groups from "
            "repeated JWT-authenticated gateway requests"
        )
        return resolved

    def _verify_federated_principal_discovery(self, port: int) -> None:
        """Prove Keycloak-federated and direct LDAP discovery against one LDAP identity."""
        fixture = self.principal_scenarios["federation"]
        identity = fixture["ldap_identity"]
        realm = json.loads((CONFIG_DIR / "keycloak-realm.json").read_text(encoding="utf-8"))
        static_usernames = {
            user.get("username") for user in realm.get("users", []) if user.get("username")
        }
        if identity["username"] in static_usernames:
            raise RuntimeError(
                "federated LDAP identity must not be embedded in the Keycloak realm fixture"
            )

        keycloak_candidate = self._search_external_principal(
            port,
            provider_id=fixture["keycloak"]["provider_id"],
            identity=identity,
            expected_issuer=self.issuer,
        )
        keycloak_principal = self._materialize_idempotently(port, keycloak_candidate)

        direct = fixture["direct_ldap"]
        ldap_candidate = self._search_external_principal(
            port,
            provider_id=direct["provider_id"],
            identity=identity,
            expected_issuer=direct["issuer"],
            expected_external_id=identity["immutable_external_id"],
        )
        ldap_principal = self._materialize_idempotently(port, ldap_candidate)
        if keycloak_principal["id"] == ldap_principal["id"]:
            raise RuntimeError(
                "Keycloak and direct LDAP projections unexpectedly share an issuer-local key"
            )
        if keycloak_principal["issuer"] == ldap_principal["issuer"]:
            raise RuntimeError("federated providers did not preserve distinct issuer namespaces")

        self.details.extend(
            [
                "Authguard -> Keycloak Admin API discovered and idempotently materialized "
                "one LDAP-only user absent from the static realm fixture",
                "Authguard direct LDAP (RFC 4511) discovery resolved the same directory "
                "identity by immutable entry UUID and materialized it idempotently",
            ]
        )

    def _verify_scim_principal_discovery(
        self,
        port: int,
        jit_principals: dict[str, dict[str, dict]],
    ) -> None:
        """Prove SCIM User/Group lifecycle and convergence with OIDC JIT keys."""
        fixture = self.principal_scenarios["scim"]
        provider_id = fixture["provider_id"]
        user_payload = json.loads(json.dumps(fixture["user"]))
        group_payload = json.loads(json.dumps(fixture["group"]))
        user_external_id = user_payload["resource"]["externalId"]
        group_external_id = f"group:{group_payload['resource']['externalId']}"

        self._verify_scim_lifecycle(
            port,
            provider_id=provider_id,
            payload=user_payload,
            external_id=user_external_id,
            expected_kind="USER",
        )
        self._verify_scim_lifecycle(
            port,
            provider_id=provider_id,
            payload=group_payload,
            external_id=group_external_id,
            expected_kind="GROUP",
        )

        jit_user = jit_principals["users"]["direct-reader"]
        converged_user = json.loads(json.dumps(user_payload))
        converged_user["resource"].update(
            {
                "id": "scim-jit-user-convergence",
                "externalId": jit_user["external_id"],
                "userName": "direct-reader",
                "display_name": "Direct Reader",
            }
        )
        projected = self._scim_refresh(port, converged_user)
        if projected["id"] != jit_user["id"]:
            raise RuntimeError("SCIM User did not converge on the existing OIDC JIT Principal")
        self._expect_single_principal(
            port,
            issuer=self.issuer,
            external_id=jit_user["external_id"],
            expected_kind="USER",
        )

        jit_group = jit_principals["groups"]["direct-readers"]
        converged_group = json.loads(json.dumps(group_payload))
        converged_group["resource"].update(
            {
                "id": "scim-jit-group-convergence",
                "externalId": jit_group["external_id"].removeprefix("group:"),
                "displayName": "Direct Readers",
            }
        )
        projected = self._scim_refresh(port, converged_group)
        if projected["id"] != jit_group["id"]:
            raise RuntimeError("SCIM Group did not converge on the existing OIDC JIT Principal")
        self._expect_single_principal(
            port,
            issuer=self.issuer,
            external_id=jit_group["external_id"],
            expected_kind="GROUP",
        )
        self.details.extend(
            [
                "SCIM RFC 7643 User and Group refreshes were idempotent across "
                "upsert, disable, and reactivation lifecycle transitions",
                "SCIM and OIDC JIT converged on one local Principal for each identical "
                "(issuer, external_id) key",
            ]
        )

    def _verify_scim_lifecycle(
        self,
        port: int,
        *,
        provider_id: str,
        payload: dict,
        external_id: str,
        expected_kind: str,
    ) -> None:
        first = self._scim_refresh(port, payload)
        second = self._scim_refresh(port, payload)
        if first["id"] != second["id"]:
            raise RuntimeError(f"SCIM {expected_kind} upsert was not idempotent")
        active = self._expect_single_principal(
            port,
            issuer=self.issuer,
            external_id=external_id,
            expected_kind=expected_kind,
        )
        if active["id"] != first["id"]:
            raise RuntimeError(f"SCIM {expected_kind} lookup returned a different projection")

        deleted = self._scim_refresh(
            port,
            {
                "operation": "delete",
                "resource": {
                    "provider_id": provider_id,
                    "issuer": self.issuer,
                    "external_id": external_id,
                },
            },
        )
        if deleted["id"] != first["id"] or deleted.get("status") != "DISABLED":
            raise RuntimeError(f"SCIM {expected_kind} delete did not retain a disabled tombstone")
        disabled = self._expect_single_principal(
            port,
            issuer=self.issuer,
            external_id=external_id,
            expected_kind=expected_kind,
            expected_status="DISABLED",
        )
        if disabled["id"] != first["id"]:
            raise RuntimeError(f"SCIM {expected_kind} tombstone changed its local identifier")

        reactivated = self._scim_refresh(port, payload)
        if reactivated["id"] != first["id"] or reactivated.get("status") != "ACTIVE":
            raise RuntimeError(f"SCIM {expected_kind} upsert did not reactivate its tombstone")

    def _search_external_principal(
        self,
        port: int,
        *,
        provider_id: str,
        identity: dict,
        expected_issuer: str,
        expected_external_id: str | None = None,
    ) -> dict:
        status, body = self._admin_http(
            port,
            "/adm/v1/principal-discovery/search",
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
        for candidate in json.loads(body).get("principals", []):
            reference = candidate.get("reference", {})
            if (
                reference.get("provider_id") == provider_id
                and reference.get("issuer") == expected_issuer
                and candidate.get("username") == identity["username"]
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
            or candidate.get("display_name") != identity["display_name"]
            or candidate.get("email") != identity["email"]
            or candidate.get("enabled") is not True
            or not candidate["reference"].get("external_id")
        ):
            raise RuntimeError(
                f"{provider_id}: federated Principal attributes do not match fixture"
            )
        return candidate

    def _materialize_idempotently(self, port: int, candidate: dict) -> dict:
        reference = candidate["reference"]
        persisted: list[dict] = []
        for attempt in (1, 2):
            status, body = self._admin_http(
                port,
                "/adm/v1/principal-discovery/materialize",
                method="POST",
                json_body=reference,
            )
            self._expect_status(
                f"materialize {reference['provider_id']} attempt {attempt}", status, 201
            )
            persisted.append(json.loads(body))
        if persisted[0]["id"] != persisted[1]["id"]:
            raise RuntimeError(
                f"{reference['provider_id']}: repeated materialization changed local identifier"
            )
        local = self._expect_single_principal(
            port,
            issuer=reference["issuer"],
            external_id=reference["external_id"],
            expected_kind=candidate["kind"],
        )
        if local["id"] != persisted[0]["id"]:
            raise RuntimeError(
                f"{reference['provider_id']}: materialized projection cannot be resolved exactly"
            )
        if local.get("attributes", {}).get("provider_id") != reference["provider_id"]:
            raise RuntimeError(
                f"{reference['provider_id']}: local projection lost its discovery source"
            )
        return local

    def _scim_refresh(self, port: int, payload: dict) -> dict:
        status, body = self._admin_http(
            port,
            "/adm/v1/principal-discovery/scim/refresh",
            method="POST",
            json_body=payload,
        )
        self._expect_status(f"SCIM {payload['operation']}", status, 200)
        projected = json.loads(body)
        if not isinstance(projected, dict) or not projected.get("id"):
            raise RuntimeError("SCIM refresh did not return a persisted Principal")
        return projected

    def _expect_single_principal(
        self,
        port: int,
        *,
        issuer: str,
        external_id: str,
        expected_kind: str,
        expected_status: str = "ACTIVE",
    ) -> dict:
        matches = self._find_exact_principals(port, issuer, external_id)
        if len(matches) != 1:
            raise RuntimeError(
                "expected exactly one local Principal for the external identity key; "
                f"found {len(matches)}"
            )
        principal = matches[0]
        if (
            principal.get("kind") != expected_kind
            or principal.get("status") != expected_status
        ):
            raise RuntimeError(
                "local Principal has unexpected kind or status: "
                f"expected {expected_kind}/{expected_status}"
            )
        return principal

    def _find_exact_principals(
        self,
        port: int,
        issuer: str,
        external_id: str,
    ) -> list[dict]:
        query = parse.urlencode({"query": external_id, "limit": 100})
        status, body = self._admin_http(port, f"/adm/v1/principals?{query}")
        self._expect_status("exact local Principal lookup", status, 200)
        return [
            principal
            for principal in json.loads(body).get("items", [])
            if principal.get("issuer") == issuer
            and principal.get("external_id") == external_id
        ]

    def _required_string_claim(self, token: str, claim: str) -> str:
        value = self._jwt_claims(token).get(claim)
        if not isinstance(value, str) or not value:
            raise RuntimeError(f"Keycloak JWT is missing required {claim!r} claim")
        return value

    def _required_group_principal_ids(self, port: int) -> dict[str, str]:
        resolved: dict[str, str] = {}
        for group, external_id in GROUP_EXTERNAL_IDS.items():
            principal = self._expect_single_principal(
                port,
                issuer=self.issuer,
                external_id=external_id,
                expected_kind="GROUP",
            )
            resolved[group] = principal["id"]
        return resolved

    def _verify_workload_contract(
        self,
        gateway_port: int,
        component: str,
        host: str,
        direct_token: str,
        editor_token: str,
    ) -> None:
        label = f"e2e-{component}"
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

        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs",
            method="POST",
            headers={"Authorization": f"Bearer {direct_token}"},
            json_body={**created, "id": 102, "job_id": "forbidden-create"},
        )
        self._expect_status(f"{label}: read-only create is forbidden", status, 403)
        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/102",
            headers={"Authorization": f"Bearer {editor_token}"},
        )
        self._expect_status(f"{label}: rejected create does not mutate", status, 404)

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

    def _clean_previous_release(self) -> None:
        for release in (
            self.authguard_release,
            self.support_release,
            self.envoy_release,
        ):
            self._run(
                ("helm", "uninstall", release, "-n", self.namespace, "--wait"),
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
                str(PROJECT_ROOT / "deploy" / "docker" / "authguard.Dockerfile"),
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
        for image in external_images:
            inspected = self._run(
                ("docker", "image", "inspect", image), allowed_codes={0, 1}
            )
            if inspected.return_code != 0:
                self._run(("docker", "pull", image))
        cluster_images = set(
            self._run(
                (*self._k3s_command(), "ctr", "-n", "k8s.io", "images", "list", "-q")
            ).output.splitlines()
        )
        for image in external_images:
            if image not in cluster_images:
                self._import_image(image)
            else:
                self.details.append(f"reuse k3s image: {image}")

    def _prepare_workload_images(self) -> None:
        # e2e-local tags are intentionally mutable. Import them immediately before
        # creating their Pods so k3s image GC cannot collect an unreferenced image
        # while an earlier Helm release is still becoming ready.
        for image in WORKLOAD_IMAGES.values():
            self._import_image(image)

    def _import_image(self, image: str) -> None:
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
        grpc_target = f"e2e-customer-growth-authguard.{self.namespace}.svc.cluster.local:8081"
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
                "--set",
                f"authguard.grpcTarget={grpc_target}",
                "--set",
                f"gateway.name={self.gateway_name}",
                "--wait",
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
        return {
            "envoy-gateway": {
                "enabled": False,
                "global": {
                    "images": {
                        "envoyProxy": {
                            "image": ALIYUN_ENVOY_IMAGE,
                            "pullPolicy": "Never",
                        }
                    }
                },
            },
            "redis-cluster": {
                "enabled": True,
                "image": {
                    "registry": "registry.cn-shenzhen.aliyuncs.com",
                    "repository": "wl4g-k8s/bitnami_redis-cluster",
                    "tag": "7.0.14",
                    "pullPolicy": "Never",
                },
                "password": "e2e-redis-password",
                "cluster": {"nodes": 6, "replicas": 1},
                "persistence": {"enabled": False},
            },
            "authguardIntegration": {
                "enabled": True,
                "gateway": {
                    "create": True,
                    "className": self.gateway_name,
                    "name": self.gateway_name,
                },
                "jwt": {
                    "enabled": True,
                    "issuer": self.issuer,
                    "audiences": ["customer-growth-job-service"],
                    "localJWKS": {"existingConfigMap": "", "inline": ""},
                    "remoteJWKS": {
                        "uri": f"{self.issuer}/protocol/openid-connect/certs",
                        "backendRefs": [
                            {"name": self.keycloak_service, "port": 8080}
                        ],
                    },
                },
                "oidc": {"enabled": False},
                "exampleRoute": {"enabled": False},
                "tracing": {
                    "enabled": True,
                    "backendRef": {"name": self.jaeger_service, "port": 4317},
                    "serviceName": "e2e-envoy-proxy",
                },
            },
            "fullnameOverride": "e2e-customer-growth-authguard",
            "authguard": {
                "replicaCount": 1,
                "image": {
                    "repository": AUTHGUARD_IMAGE.rsplit(":", 1)[0],
                    "tag": AUTHGUARD_IMAGE.rsplit(":", 1)[1],
                    "pullPolicy": "Never",
                },
                "disruptionBudget": {"enabled": False},
                "admin": {"token": AUTHGUARD_ADMIN_TOKEN},
                "principalDiscovery": {
                    "existingSecret": self.principal_discovery_secret,
                },
                "accessContext": {
                    "existingSecret": E2E_ACCESS_CONTEXT_SECRET,
                    "key": "hmac-key",
                },
                "config": {
                    "server": {"service_name": "e2e-authguard"},
                    "mgmt": {
                        "otel": {
                            "enabled": True,
                            "endpoint": (
                                f"http://{self.jaeger_service}.{self.namespace}"
                                ".svc.cluster.local:4317"
                            ),
                            "protocol": "grpc",
                            "timeout": "5s",
                            "sample_rate": 1.0,
                        }
                    },
                    "auth": {
                        "principal_discovery": {
                            "jit": {"allow_insecure_http": True},
                            "federated": {
                                "keycloak": [
                                    {
                                        "discovery_id": "e2e-keycloak-ldap",
                                        "base_url": (
                                            f"http://{self.keycloak_service}.{self.namespace}"
                                            ".svc.cluster.local:8080"
                                        ),
                                        "issuer": self.issuer,
                                        "realm": "example-corp",
                                        "client_id": "e2e-authguard-principal-discovery",
                                        "client_secret": "",
                                        "client_secret_file": (
                                            "/etc/authguard/principal-discovery/"
                                            "keycloak-client-secret"
                                        ),
                                        "connect_timeout": "3s",
                                        "request_timeout": "10s",
                                        "max_page_size": 100,
                                        "allow_insecure_http": True,
                                    }
                                ],
                                "ldap": [
                                    {
                                        "discovery_id": "e2e-direct-ldap",
                                        "url": (
                                            f"ldap://{self.ldap_service}.{self.namespace}"
                                            ".svc.cluster.local:389"
                                        ),
                                        "issuer": (
                                            "urn:authguard:e2e:ldap:example-corp"
                                        ),
                                        "base_dn": "dc=example,dc=org",
                                        "bind_dn": (
                                            "cn=svc-authguard,ou=Users,"
                                            "dc=example,dc=org"
                                        ),
                                        "bind_password": "",
                                        "bind_password_file": (
                                            "/etc/authguard/principal-discovery/"
                                            "ldap-bind-password"
                                        ),
                                        "user": {
                                            "search_base": "",
                                            "object_filter": "(objectClass=posixAccount)",
                                            "id_attribute": "entryUUID",
                                            "name_attribute": "cn",
                                            "display_name_attribute": "displayName",
                                            "email_attribute": "mail",
                                            "enabled_attribute": None,
                                            "search_attributes": [
                                                "cn",
                                                "displayName",
                                                "mail",
                                                "entryUUID",
                                            ],
                                        },
                                        "group": {
                                            "search_base": "",
                                            "object_filter": "(objectClass=posixGroup)",
                                            "id_attribute": "gidNumber",
                                            "name_attribute": "ou",
                                            "display_name_attribute": "ou",
                                            "email_attribute": None,
                                            "enabled_attribute": None,
                                            "search_attributes": [
                                                "ou",
                                                "gidNumber",
                                            ],
                                        },
                                        "connect_timeout": "3s",
                                        "request_timeout": "10s",
                                        "max_page_size": 100,
                                        "allow_insecure": True,
                                    }
                                ],
                            },
                            "scim": {
                                "enabled": True,
                                "discovery_id": "e2e-scim",
                                "issuer": self.issuer,
                            },
                        },
                        "scope_delivery": {
                            "direct_urn_limit": 1,
                            "max_direct_header_bytes": 8192,
                            "context_ttl": "30s",
                            "scope_token_ttl": "30s",
                        }
                    },
                    "cache": {"provider": "Redis"},
                },
                "policy": self._authorization_policy(revision=0),
            },
        }

    def _authorization_policy(
        self,
        *,
        revision: int,
        group_principal_ids: dict[str, str] | None = None,
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
            "description": "JIT-projected team access for five isolated workloads",
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
        if group_principal_ids is None:
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
                "principal_id": group_principal_ids["direct-readers"],
                "role_id": "job.reader",
                "effect": "ALLOW",
                "resource_urn": f"{workspace}/**",
                "conditions": {},
            },
            {
                "id": "token-editor-retention",
                "principal_id": group_principal_ids["token-editors"],
                "role_id": "job.editor",
                "effect": "ALLOW",
                "resource_urn": f"{retention}/**",
                "conditions": {},
            },
            {
                "id": "token-editor-forecast-read",
                "principal_id": group_principal_ids["token-editors"],
                "role_id": "job.reader",
                "effect": "ALLOW",
                "resource_urn": forecast,
                "conditions": {},
            },
            {
                "id": "token-editor-vip-deny",
                "principal_id": group_principal_ids["token-editors"],
                "role_id": "job.reader",
                "effect": "DENY",
                "resource_urn": f"{retention}/job/vip-retention-risk-audit",
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
            "e2e-customer-growth-authguard",
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

    def _wait_for_gateway_api_acceptance(self) -> None:
        deadline = time.monotonic() + self.context.timeout_seconds
        expected_routes = {
            self.workload_service(component) for component in WORKLOAD_IMAGES
        }
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
                elif kind == "SecurityPolicy" and name == "e2e-customer-growth-authguard":
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
                    "Gateway, five HTTPRoutes, and SecurityPolicy are accepted"
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

        jwt = spec.get("jwt", {})
        providers = jwt.get("providers", [])
        provider = next(
            (candidate for candidate in providers if candidate.get("issuer") == self.issuer),
            None,
        )
        if jwt.get("optional") is not False or provider is None:
            raise RuntimeError("SecurityPolicy does not require the E2E Keycloak issuer")
        if "customer-growth-job-service" not in provider.get("audiences", []):
            raise RuntimeError("SecurityPolicy does not validate the workload JWT audience")
        jwks_backends = provider.get("remoteJWKS", {}).get("backendRefs", [])
        if not any(
            backend.get("name") == self.keycloak_service and backend.get("port") == 8080
            for backend in jwks_backends
        ):
            raise RuntimeError("SecurityPolicy does not load JWKS from the E2E Keycloak service")
        self.details.append(
            "SecurityPolicy requires the Keycloak issuer/audience and remote JWKS, then "
            "calls fail-closed Authguard ext_auth gRPC on port 8080"
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
            self._expect_status("tampered Keycloak JWT rejected by Envoy", status, 401)
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
            self._expect_status("valid Keycloak JWT passed Envoy and ext_auth", status, 200)
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
            "tampered JWT caused zero Authguard Check calls; valid Keycloak JWT caused "
            "exactly one envoy.service.auth.v3.Authorization/Check call"
        )

    @staticmethod
    def _tamper_jwt_signature(token: str) -> str:
        parts = token.split(".")
        if len(parts) != 3 or not parts[2]:
            raise RuntimeError("Keycloak returned a malformed signed JWT")
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

    def _verify_distributed_trace(self, gateway_port: int, host: str) -> None:
        trace = E2ETrace("customer-growth.authorization.e2e")
        token_span = trace.start_client(
            "keycloak.token",
            **{"server.address": self.keycloak_service, "http.request.method": "POST"},
        )
        with self._forward_service(self.keycloak_service, 8080) as keycloak_port:
            token = self._password_token(
                keycloak_port,
                "direct-reader",
                "direct-reader-password",
                headers={
                    "traceparent": token_span.traceparent,
                    "x-request-id": trace.request_id,
                },
            )
        token_span.finish()

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
                "Authorization": f"Bearer {token}",
                "traceparent": gateway_span.traceparent,
                "x-request-id": trace.request_id,
            },
        )
        gateway_span.finish()
        self._expect_status("OTel-correlated authorized request", status, 200)

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

        with self._forward_service(self.jaeger_service, 16686) as query_port:
            verifier = JaegerTraceVerifier(keycloak_service=self.keycloak_service)
            payload = self._wait_for_distributed_trace(
                query_port,
                trace,
                verifier,
            )
        verifier.verify(payload, trace)
        self.details.extend(
            [
                "Jaeger verified one W3C trace with verifier, Keycloak, Envoy Proxy, "
                "and Authguard spans",
                f"Jaeger trace ID: {trace.trace_id}",
                (
                    "Jaeger UI: kubectl -n "
                    f"{self.namespace} port-forward service/{self.jaeger_service} "
                    "16686:16686, then open "
                    f"http://127.0.0.1:16686/trace/{trace.trace_id}"
                ),
            ]
        )

    def _wait_for_distributed_trace(
        self,
        port: int,
        trace: E2ETrace,
        verifier: JaegerTraceVerifier,
    ) -> dict:
        deadline = time.monotonic() + min(self.context.timeout_seconds, 90)
        last_failure = "trace was not returned"
        while time.monotonic() < deadline:
            try:
                with request.urlopen(
                    f"http://127.0.0.1:{port}/api/traces/{trace.trace_id}",
                    timeout=10,
                ) as response:
                    payload = json.loads(response.read())
                verifier.verify(payload, trace)
                return payload
            except (error.HTTPError, error.URLError, RuntimeError, ValueError) as failure:
                last_failure = str(failure)
                time.sleep(1)
        raise RuntimeError(
            f"Jaeger trace {trace.trace_id} did not become complete: {last_failure}"
        )

    def _expect_token_claims(self, token: str, expected_group: str) -> None:
        claims = self._jwt_claims(token)
        if claims.get("tenant_id") != "example-corp":
            raise RuntimeError("Keycloak token is missing the example-corp tenant claim")
        if claims.get("authguard_group") != expected_group:
            raise RuntimeError(
                "Keycloak token has the wrong scalar authguard_group claim: "
                f"expected {expected_group!r}, got {claims.get('authguard_group')!r}"
            )
        expected_group_id = GROUP_EXTERNAL_IDS[expected_group].removeprefix("group:")
        if claims.get("authguard_group_ids") != [expected_group_id]:
            raise RuntimeError(
                "Keycloak token has the wrong stable authguard_group_ids claim: "
                f"expected {[expected_group_id]!r}, "
                f"got {claims.get('authguard_group_ids')!r}"
            )
        self.details.append(
            f"Keycloak emitted tenant, condition, and stable group ID claims for {expected_group}"
        )

    @staticmethod
    def _jwt_claims(token: str) -> dict:
        parts = token.split(".")
        if len(parts) != 3:
            raise RuntimeError("Keycloak returned a malformed JWT")
        encoded = parts[1] + "=" * (-len(parts[1]) % 4)
        try:
            claims = json.loads(base64.urlsafe_b64decode(encoded))
        except (ValueError, json.JSONDecodeError) as failure:
            raise RuntimeError("Keycloak returned an invalid JWT payload") from failure
        if not isinstance(claims, dict):
            raise RuntimeError("Keycloak JWT payload is not an object")
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

    def _admin_http(
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
                "Authorization": f"Bearer {AUTHGUARD_ADMIN_TOKEN}",
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

    def _verify_metrics(self) -> None:
        with self._forward_service("e2e-customer-growth-authguard", 9091) as port:
            with request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=15) as response:
                metrics = response.read().decode()
        for metric in (
            'authguard_scope_deliveries_total{mode="direct"}',
            'authguard_scope_deliveries_total{mode="token"}',
            'authguard_scope_resolutions_total{outcome="hit"}',
        ):
            if metric not in metrics:
                raise RuntimeError(f"expected runtime metric is missing: {metric}")
        self.details.append("direct and opaque-token delivery metrics observed")

    def _verify_authguard_check_logs(self) -> None:
        result = self._run(
            (
                "kubectl",
                "logs",
                "-n",
                self.namespace,
                f"deployment/{self.authguard_release}",
                "--tail=1000",
            )
        )
        check_events = 0
        discovery_events: set[str] = set()
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
            if discovery in {"jit", "federation", "scim"}:
                discovery_events.add(discovery)
        if check_events == 0:
            raise RuntimeError("Authguard logs contain no Envoy Authorization/Check events")
        missing_discovery = {"jit", "federation", "scim"} - discovery_events
        if missing_discovery:
            raise RuntimeError(
                "Authguard structured logs lack Principal discovery evidence: "
                + ", ".join(sorted(missing_discovery))
            )
        self.details.append(
            f"Authguard structured logs contain {check_events} "
            "envoy.service.auth.v3.Authorization/Check events"
        )
        self.details.append(
            "Authguard structured logs contain JIT, federation, and SCIM discovery events"
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
                "app.kubernetes.io/component=e2e-postgresql",
                "-o",
                "jsonpath={.items[0].metadata.name}",
            )
        ).output.strip()
        sql = (
            "SELECT "
            "(SELECT count(*) FROM information_schema.schemata WHERE schema_name IN "
            "('e2e_customer_growth_go_sqlx','e2e_customer_growth_rust_sqlx','e2e_customer_growth_python_sqlalchemy','e2e_customer_growth_spring_jdbc','e2e_customer_growth_spring_jpa')) || '|' || "
            "(SELECT count(*) FROM information_schema.tables WHERE table_name='customer_growth_jobs' AND table_schema LIKE 'e2e_%') || '|' || "
            "CASE WHEN has_schema_privilege('e2e_customer_growth_go_sqlx','e2e_customer_growth_rust_sqlx','USAGE') "
            "THEN 1 ELSE 0 END"
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
        if isolation != "5|5|0":
            raise RuntimeError(
                f"PostgreSQL schema isolation mismatch: expected 5|5|0, got {isolation!r}"
            )
        self.details.append(
            "five e2e_ PostgreSQL schemas exist and cross-schema USAGE is denied"
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
        pod = self._run(
            (
                "kubectl",
                "get",
                "pods",
                "-n",
                self.namespace,
                "-l",
                f"gateway.envoyproxy.io/owning-gateway-name={self.gateway_name}",
                "-o",
                "jsonpath={.items[0].metadata.name}",
            )
        ).output.strip()
        if not pod:
            raise RuntimeError("Envoy Proxy pod was not created")
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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


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
