"""Phase 00: deploy and validate the complete real E2E topology."""

from __future__ import annotations

import json
import time
from urllib import request

from common.kubernetes import (
    ALIYUN_ENVOY_GATEWAY_IMAGE,
    ALIYUN_ENVOY_IMAGE,
    ALIYUN_JAEGER_IMAGE,
    ALIYUN_KEYCLOAK_IMAGE,
    ALIYUN_LDAP_IMAGE,
    ALIYUN_POSTGRES_IMAGE,
    ALIYUN_REDIS_IMAGE,
    AUTHGUARD_IMAGE,
    E2E_KEYS_DIR,
    WORKLOAD_IMAGES,
    _has_true_condition,
)
from common.model import RunContext, VerificationResult
from verifier.base_verifier import BaseVerifier


class InfrastructureVerifier(BaseVerifier):
    scenario_id = "00"
    title = "Infrastructure: Helm deployment and middleware initialization"

    def run(self) -> VerificationResult:
        return self.execute(self._run_scenario)

    def _run_scenario(self) -> None:
        self.step(
            "verify Docker, Helm, kubectl, and k3s prerequisites",
            self.infrastructure.verify_prerequisites,
        )
        self.step(
            "clean and deploy Envoy, middleware, AuthN/AuthZ, and five Biz services",
            self.infrastructure.redeploy,
        )
        self.step(
            "wait for accepted Gateway API resources",
            self._wait_for_gateway_api_acceptance,
        )
        self.step(
            "verify Keycloak, LDAP, mock IdP, and Secret initialization",
            self._verify_identity_middleware_initialization,
        )
        self.step("verify Redis Cluster health", self._verify_redis_cluster)
        self.step("verify immutable running images", self._verify_running_images)
        self.step("verify zero container restarts", self._verify_zero_container_restarts)

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


def verify(context: RunContext) -> VerificationResult:
    return InfrastructureVerifier(context).run()
