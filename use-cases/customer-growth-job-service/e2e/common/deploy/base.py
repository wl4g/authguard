"""Shared lifecycle and runtime operations for E2E deployment backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager
import os
from pathlib import Path
import json
import shutil
import socket
from typing import Iterator
from urllib import parse, request

from ..config import E2E_DIR, PROJECT_ROOT
from ..model import CommandResult, RunContext
from ..process import run_command


ALIYUN_ENVOY_IMAGE = (
    "registry.cn-shenzhen.aliyuncs.com/wl4g/envoyproxy_envoy:distroless-v1.36.4"
)
ALIYUN_ENVOY_GATEWAY_IMAGE = (
    "registry.cn-shenzhen.aliyuncs.com/wl4g/envoyproxy_gateway:v1.9.0"
)
ALIYUN_REDIS_IMAGE = (
    "registry.cn-shenzhen.aliyuncs.com/wl4g-k8s/bitnami_redis-cluster:7.0.14"
)
ALIYUN_DOCKER_REDIS_IMAGE = ALIYUN_REDIS_IMAGE
ALIYUN_KEYCLOAK_IMAGE = "registry.cn-shenzhen.aliyuncs.com/wl4g/keycloak:26.7.0"
ALIYUN_LDAP_IMAGE = "registry.cn-shenzhen.aliyuncs.com/wl4g/glauth:v2.5.0"
ALIYUN_JAEGER_IMAGE = (
    "registry.cn-shenzhen.aliyuncs.com/wl4g/jaegertracing_all-in-one:1.76.0"
)
ALIYUN_POSTGRES_IMAGE = (
    "registry.cn-shenzhen.aliyuncs.com/wl4g/bitnami_postgresql:18.3"
)
ALIYUN_ANVIL_IMAGE = "registry.cn-shenzhen.aliyuncs.com/wl4g/foundry_anvil:1.7.1"
ALIYUN_SOLANA_IMAGE = "registry.cn-shenzhen.aliyuncs.com/wl4g/anza_solana:3.1.14"
DEFAULT_AUTHGUARD_IMAGE = (
    "registry.cn-shenzhen.aliyuncs.com/wl4g/authguard:e2e-local"
)
DEFAULT_AUTHGUARD_WEB_IMAGE = (
    "registry.cn-shenzhen.aliyuncs.com/wl4g/authguard-web:e2e-local"
)
AUTHGUARD_IMAGE = os.getenv("AUTHGUARD_E2E_AUTHGUARD_IMAGE", DEFAULT_AUTHGUARD_IMAGE)
AUTHGUARD_WEB_IMAGE = os.getenv(
    "AUTHGUARD_E2E_WEB_IMAGE", DEFAULT_AUTHGUARD_WEB_IMAGE
)
AUTHGUARD_API_TOKEN = "e2e-authguard-api-token"
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
CUSTOMER_GROWTH_HOST = "customer-growth.local"
CUSTOMER_GROWTH_FALLBACK_HOST = "customer-growth-default.local"
AUTHN_BROWSER_HOST = "localhost"
LOCAL_PORT_RANGE = range(28800, 28900)
GROUP_EXTERNAL_IDS = {
    "direct-readers": "group:11111111-1111-4111-8111-111111111111",
    "token-editors": "group:22222222-2222-4222-8222-222222222222",
}
GROUP_PRINCIPAL_IDS = {
    "direct-readers": "principal-direct-readers",
    "token-editors": "principal-token-editors",
}


class BaseE2EDeployer(ABC):
    """Backend-neutral contract used by every ordered E2E verifier."""

    backend = ""

    def __init__(self, context: RunContext) -> None:
        self.context = context
        self.environment: dict[str, str] = {}
        self.commands: list[CommandResult] = []
        self.details: list[str] = []
        self.deploy_dir = E2E_DIR / "deploy"

    @abstractmethod
    def verify_prerequisites(self) -> None:
        """Fail unless all tools and runtime dependencies are available."""

    @abstractmethod
    def redeploy(self) -> None:
        """Create a clean, complete E2E topology."""

    @abstractmethod
    def cleanup(self) -> None:
        """Remove only resources owned by this E2E backend."""

    @abstractmethod
    @contextmanager
    def _forward_service(self, service: str, remote_port: int) -> Iterator[int]:
        """Expose one internal service port on loopback for the verifier."""
        yield 0

    @abstractmethod
    @contextmanager
    def _forward_envoy_admin(self) -> Iterator[int]:
        """Expose the active Envoy admin port on loopback."""
        yield 0

    @abstractmethod
    def service_logs(self, service: str, tail: int = 5000) -> str:
        """Return recent logs for one logical service."""

    @abstractmethod
    def postgresql_query(self, sql: str) -> str:
        """Run a fail-closed query against the E2E PostgreSQL database."""

    @abstractmethod
    def internal_hostname(self, service: str) -> str:
        """Return the DNS name used by containers for another service."""

    def service_url(self, service: str, port: int, scheme: str) -> str:
        return f"{scheme}://{self.internal_hostname(service)}:{port}"

    @property
    @abstractmethod
    def redis_node(self) -> str:
        """Return the Redis connection URL used by AuthGuard."""

    @property
    @abstractmethod
    def iam_postgres_url(self) -> str:
        """Return the IAM PostgreSQL connection URL used by AuthGuard."""

    def solana_chain_reference(self) -> str:
        """Derive the CAIP-2 reference from the live local validator genesis."""
        genesis_hash = self.json_rpc(self.solana_service, 8899, "getGenesisHash")
        if not isinstance(genesis_hash, str) or len(genesis_hash) < 32:
            raise RuntimeError(
                f"local Solana validator returned invalid genesis: {genesis_hash!r}"
            )
        return genesis_hash[:32]

    def json_rpc(
        self,
        service: str,
        remote_port: int,
        method: str,
        params: list[object] | None = None,
    ) -> object:
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
        ).encode()
        with self._forward_service(service, remote_port) as port:
            outgoing = request.Request(
                f"http://127.0.0.1:{port}",
                data=payload,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with request.urlopen(outgoing, timeout=15) as response:
                result = json.loads(response.read())
        if "error" in result or "result" not in result:
            raise RuntimeError(f"{service} JSON-RPC {method} failed: {result}")
        return result["result"]

    def _authguard_runtime_config(self) -> str:
        """Full authguard.yaml main configuration for the E2E deployment."""
        keycloak_base = self.service_url(self.keycloak_service, 8080, "http")
        jaeger_endpoint = self.service_url(self.jaeger_service, 4317, "http")
        ldap_url = self.service_url(self.ldap_service, 389, "ldap")
        mock_idp_url = self.service_url(self.mock_idp_service, 8080, "http")
        anvil_rpc_url = self.service_url(self.anvil_service, 8545, "http")
        solana_reference = self.solana_chain_reference()
        redis_node = self.redis_node
        iam_postgres_url = self.iam_postgres_url
        # ${KEY} references resolve from the selected backend's runtime environment.
        return "\n".join(
            [
                "authn:",
                "  applications:",
                "    customer-growth:",
                f"      hosts: [{AUTHN_BROWSER_HOST}, {CUSTOMER_GROWTH_HOST}]",
                "      displayName: Customer Growth",
                "      logo: /auth/assets/themes/custom/customer-growth.svg",
                "      theme:",
                "        id: customer-growth",
                "        stylesheet: /auth/assets/themes/custom/customer-growth.css",
                "      returnUris:",
                f"        - {'https://' + AUTHN_BROWSER_HOST + '/**'!r}",
                f"        - {'https://' + CUSTOMER_GROWTH_HOST + '/**'!r}",
                "    customer-growth-default:",
                f"      hosts: [{CUSTOMER_GROWTH_FALLBACK_HOST}]",
                "      displayName: Customer Growth",
                f"      returnUris: [{'https://' + CUSTOMER_GROWTH_FALLBACK_HOST + '/**'!r}]",
                "  providers:",
                "    github:",
                "      type: oauth2",
                "      issuer: https://github.com",
                "      clientId: e2e-authguard-github-client",
                '      clientSecret: "${AUTHGUARD__AUTHN__PROVIDERS__GITHUB__CLIENT_SECRET}"',
                f"      callbackUrl: http://{AUTHN_BROWSER_HOST}:8082/auth/oauth2/github/callback",
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
                '      clientSecret: "${AUTHGUARD__AUTHN__PROVIDERS__GOOGLE__CLIENT_SECRET}"',
                f"      callbackUrl: http://{AUTHN_BROWSER_HOST}:8082/auth/oauth2/google/callback",
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
                '      clientSecret: "${AUTHGUARD__AUTHN__PROVIDERS__E2E_AUTHGUARD_KEYCLOAK__CLIENT_SECRET}"',
                f"      callbackUrl: http://{AUTHN_BROWSER_HOST}:8082/auth/oauth2/e2e-authguard-keycloak/callback",
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
                "          authguard_group_ids: $.authguard_group_ids",
                "    wechat:",
                "      type: oauth2-like",
                "      issuer: https://open.weixin.qq.com",
                "      clientId: e2e-authguard-wechat-app",
                '      clientSecret: "${AUTHGUARD__AUTHN__PROVIDERS__WECHAT__CLIENT_SECRET}"',
                f"      callbackUrl: http://{AUTHN_BROWSER_HOST}:8082/auth/oauth2/wechat/callback",
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
                '      clientSecret: "${AUTHGUARD__AUTHN__PROVIDERS__QQ__CLIENT_SECRET}"',
                f"      callbackUrl: http://{AUTHN_BROWSER_HOST}:8082/auth/oauth2/qq/callback",
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
                "  standalone:",
                "    enabled: true",
                "    issuer: urn:authguard:e2e:standalone",
                '    credentialEncryptionKey: "${AUTHGUARD__AUTHN__STANDALONE__CREDENTIAL_ENCRYPTION_KEY}"',
                "    password:",
                "      minLength: 12",
                "    totp:",
                "      enabled: true",
                "      issuer: AuthGuard E2E",
                "      digits: 6",
                "      stepSeconds: 30",
                "      skew: 1",
                "    webauthn:",
                "      enabled: true",
                f"      rpId: {AUTHN_BROWSER_HOST!r}",
                f"      rpOrigin: {'http://' + AUTHN_BROWSER_HOST + ':8082'!r}",
                "      rpName: AuthGuard Customer Growth E2E",
                "  wallet:",
                "    enabled: true",
                f"    domain: {AUTHN_HOST + ':8082'!r}",
                f"    uri: {'http://' + AUTHN_HOST + ':8082'!r}",
                "    statement: Sign in to Customer Growth",
                "    rpcTimeout: 2s",
                "    chains:",
                "      eip155:",
                # EOA verification must remain fully offline. RPC is present only
                # on the independent contract-wallet and fault-injection chains.
                "        '31336': {}",
                "        '31337':",
                f"          rpc: {anvil_rpc_url!r}",
                "        '31338':",
                f"          rpc: {mock_idp_url + '/fault/ethereum/31338/timeout'!r}",
                f"      solana: [{solana_reference}]",
                "      bip122:",
                "        000000000019d6689c085ae165831e93:",
                "          network: bitcoin-mainnet",
                "  accountLinking:",
                "    strategy: first-login",
                "    authoritativeProviders: []",
                "    allowLink:",
                "      github: [standalone, wallet]",
                "      standalone: [wallet]",
                "  challengeTtl: 2m",
                "  token:",
                f"    issuer: {self.authn_issuer!r}",
                "    audience: customer-growth-job-service",
                "    ttl: 5m",
                '    privateKeyB64: "${AUTHGUARD__AUTHN__TOKEN__PRIVATE_KEY_B64}"',
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
                '    direct_context_hmac_key: "${AUTHGUARD__AUTHZ__SCOPE_DELIVERY__DIRECT_CONTEXT_HMAC_KEY}"',
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
                '          client_secret: "${AUTHGUARD__AUTHZ__PRINCIPAL_DISCOVERY__KEYCLOAK__INDEX_0__AUTH__CLIENT_SECRET}"',
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
                '          bind_password: "${AUTHGUARD__AUTHZ__PRINCIPAL_DISCOVERY__LDAP__INDEX_0__AUTH__BIND_PASSWORD}"',
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
                '  api_token: "${AUTHGUARD__AUTHZ__API_TOKEN}"',
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

    def _build_images(self) -> None:
        proxy = os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY")
        build_args: tuple[str, ...] = ()
        if proxy:
            parsed_proxy = parse.urlparse(proxy)
            if not parsed_proxy.hostname or not parsed_proxy.port:
                raise ValueError("HTTPS_PROXY/HTTP_PROXY must include a host and port")
            proxy_host = parsed_proxy.hostname
            container_proxy = proxy
            if proxy_host in {"127.0.0.1", "localhost", "::1"}:
                proxy_host = "host.containers.internal"
                container_proxy = parse.urlunparse(
                    parsed_proxy._replace(netloc=f"{proxy_host}:{parsed_proxy.port}")
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
        use_prebuilt_images = os.getenv(
            "AUTHGUARD_E2E_USE_PREBUILT_IMAGES", "false"
        ).lower() in {"1", "true", "yes"}
        if use_prebuilt_images:
            if (
                AUTHGUARD_IMAGE == DEFAULT_AUTHGUARD_IMAGE
                or AUTHGUARD_WEB_IMAGE == DEFAULT_AUTHGUARD_WEB_IMAGE
            ):
                raise ValueError(
                    "prebuilt E2E mode requires AUTHGUARD_E2E_AUTHGUARD_IMAGE "
                    "and AUTHGUARD_E2E_WEB_IMAGE"
                )
            self._run(("docker", "pull", AUTHGUARD_IMAGE))
            self._run(("docker", "pull", AUTHGUARD_WEB_IMAGE))
        else:
            self._run(
                (
                    "docker",
                    "build",
                    "--network=host",
                    "--pull=false",
                    *build_args,
                    "-f",
                    str(PROJECT_ROOT / "deploy" / "docker" / "Dockerfile"),
                    "--build-arg",
                    "AUTHGUARD_CARGO_FEATURES=web3",
                    "-t",
                    AUTHGUARD_IMAGE,
                    ".",
                ),
                cwd=PROJECT_ROOT,
            )
            ui_dir = PROJECT_ROOT / "web"
            self._run(
                (
                    "docker",
                    "build",
                    "--network=host",
                    "--pull=false",
                    *build_args,
                    "-f",
                    str(ui_dir / "Dockerfile"),
                    "--build-arg",
                    f"VITE_REOWN_PROJECT_ID={os.getenv('VITE_REOWN_PROJECT_ID', '')}",
                    "-t",
                    AUTHGUARD_WEB_IMAGE,
                    str(ui_dir),
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
        if result.return_code not in (allowed_codes or {0}):
            tail = "\n".join(result.output.splitlines()[-40:])
            raise RuntimeError(
                f"command failed ({result.return_code}): {' '.join(command)}\n{tail}"
            )
        return result

    @staticmethod
    def require_executables(*executables: str) -> None:
        for executable in executables:
            if shutil.which(executable) is None:
                raise RuntimeError(f"required executable is unavailable: {executable}")

    @staticmethod
    def free_port() -> int:
        for port in LOCAL_PORT_RANGE:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                try:
                    listener.bind(("127.0.0.1", port))
                except OSError:
                    continue
                return port
        raise RuntimeError("no free E2E host port remains in 28800-28899")


def create_deployer(context: RunContext) -> BaseE2EDeployer:
    """Construct the selected backend without leaking it into verifiers."""
    if context.deployer == "kubernetes":
        from .kubernetes import KubernetesE2EDeployer

        return KubernetesE2EDeployer(context)
    if context.deployer == "docker":
        from .docker import DockerE2EDeployer

        return DockerE2EDeployer(context)
    raise ValueError(f"unsupported E2E deployer: {context.deployer}")
