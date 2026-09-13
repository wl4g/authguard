"""Disposable k3s deployment lifecycle for the gateway authorization E2E."""

from __future__ import annotations

from contextlib import contextmanager
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
from urllib import parse

from .config import CONFIG_DIR, E2E_DIR, PROJECT_ROOT
from .model import CommandResult, RunContext
from .process import run_command


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
        self.helm_chart = PROJECT_ROOT / "deploy" / "helm" / "authguard"
        self.support_chart = E2E_DIR / "helm"
        self.deploy_dir = E2E_DIR / "deploy"

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
            self.cleanup()
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

    def cleanup(self) -> None:
        """Remove every namespaced E2E Helm release and its isolated namespace."""
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
            stream=False,
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
