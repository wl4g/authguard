"""Docker Compose deployment lifecycle equivalent to the Kubernetes E2E."""

from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import time
from typing import Iterator
from urllib import error, request

from .base import (
    ALIYUN_ANVIL_IMAGE,
    ALIYUN_DOCKER_REDIS_IMAGE,
    ALIYUN_ENVOY_IMAGE,
    ALIYUN_JAEGER_IMAGE,
    ALIYUN_KEYCLOAK_IMAGE,
    ALIYUN_LDAP_IMAGE,
    ALIYUN_POSTGRES_IMAGE,
    ALIYUN_SOLANA_IMAGE,
    AUTHGUARD_IMAGE,
    AUTHGUARD_WEB_IMAGE,
    BaseE2EDeployer,
    MOCK_IDP_IMAGE,
    WORKLOAD_IMAGES,
)
from ..config import CONFIG_DIR, E2E_DIR
from ..model import RunContext


class DockerE2EDeployer(BaseE2EDeployer):
    """Own one isolated Docker Compose project and all of its volumes."""

    backend = "docker"

    def __init__(self, context: RunContext) -> None:
        super().__init__(context)
        self.project_name = os.getenv(
            "AUTHGUARD_E2E_DOCKER_PROJECT", "e2e-authguard-customer-growth"
        )
        if not self.project_name.startswith("e2e-authguard-"):
            raise ValueError(
                "AUTHGUARD_E2E_DOCKER_PROJECT must start with e2e-authguard-"
            )
        self.namespace = self.project_name
        self.release = self.project_name
        self.support_release = self.project_name
        self.authguard_release = "authz"
        self.authguard_authz_service = "authz"
        self.authguard_authn_service = "authn"
        self.authguard_web_service = "web"
        self.principal_discovery_secret = "authguard.env"
        self.compose_file = E2E_DIR / "docker-compose.yaml"
        self.runtime_dir = E2E_DIR / ".runtime" / "docker"
        self._published_ports: dict[tuple[str, int], int] = {}
        self.environment = {
            "AUTHGUARD_E2E_RUNTIME_DIR": str(self.runtime_dir),
            "AUTHGUARD_E2E_AUTHGUARD_IMAGE": AUTHGUARD_IMAGE,
            "AUTHGUARD_E2E_WEB_IMAGE": AUTHGUARD_WEB_IMAGE,
            "AUTHGUARD_E2E_ENVOY_IMAGE": ALIYUN_ENVOY_IMAGE,
            "AUTHGUARD_E2E_REDIS_IMAGE": ALIYUN_DOCKER_REDIS_IMAGE,
            "AUTHGUARD_E2E_KEYCLOAK_IMAGE": ALIYUN_KEYCLOAK_IMAGE,
            "AUTHGUARD_E2E_LDAP_IMAGE": ALIYUN_LDAP_IMAGE,
            "AUTHGUARD_E2E_JAEGER_IMAGE": ALIYUN_JAEGER_IMAGE,
            "AUTHGUARD_E2E_POSTGRES_IMAGE": ALIYUN_POSTGRES_IMAGE,
            "AUTHGUARD_E2E_ANVIL_IMAGE": ALIYUN_ANVIL_IMAGE,
            "AUTHGUARD_E2E_SOLANA_IMAGE": ALIYUN_SOLANA_IMAGE,
            "AUTHGUARD_E2E_MOCK_IDP_IMAGE": MOCK_IDP_IMAGE,
            "AUTHGUARD_E2E_GO_SQLX_IMAGE": WORKLOAD_IMAGES["go-sqlx"],
            "AUTHGUARD_E2E_RUST_SQLX_IMAGE": WORKLOAD_IMAGES["rust-sqlx"],
            "AUTHGUARD_E2E_PYTHON_SQLALCHEMY_IMAGE": WORKLOAD_IMAGES[
                "python-sqlalchemy"
            ],
            "AUTHGUARD_E2E_SPRING_JDBC_IMAGE": WORKLOAD_IMAGES["spring-jdbc"],
            "AUTHGUARD_E2E_SPRING_JPA_IMAGE": WORKLOAD_IMAGES["spring-jpa"],
        }
        if "DOCKER_HOST" in os.environ:
            self.environment["DOCKER_HOST"] = os.environ["DOCKER_HOST"]
        elif not Path("/var/run/docker.sock").exists() and Path(
            "/run/podman/podman.sock"
        ).exists():
            # The host's Docker-compatible CLI is Podman Remote. docker-compose
            # must receive the same socket explicitly or it falls back to a
            # different/nonexistent image store and attempts registry pulls.
            self.environment["DOCKER_HOST"] = "unix:///run/podman/podman.sock"

    @property
    def keycloak_service(self) -> str:
        return "keycloak"

    @property
    def postgresql_service(self) -> str:
        return "postgresql"

    @property
    def jaeger_service(self) -> str:
        return "jaeger"

    @property
    def ldap_service(self) -> str:
        return "ldap"

    @property
    def mock_idp_service(self) -> str:
        return "mock-idp"

    @property
    def anvil_service(self) -> str:
        return "anvil"

    @property
    def solana_service(self) -> str:
        return "solana"

    @property
    def issuer(self) -> str:
        return "http://keycloak:8080/realms/example-corp"

    @property
    def authn_issuer(self) -> str:
        return "urn:authguard:e2e:authn"

    @property
    def redis_node(self) -> str:
        return "redis://redis:6379"

    @property
    def iam_postgres_url(self) -> str:
        return (
            "postgresql://postgresql:5432/e2e_authguard_customer_growth"
            "?sslmode=disable&options=-csearch_path%3Dauthguard"
        )

    def workload_service(self, component: str) -> str:
        if component not in WORKLOAD_IMAGES:
            raise ValueError(f"unknown workload: {component}")
        return component

    def internal_hostname(self, service: str) -> str:
        return service

    def verify_prerequisites(self) -> None:
        self.require_executables("docker")
        self._run(("docker", "version"))
        self._run(("docker", "compose", "version"))
        self._prepare_runtime_files()
        self._compose("config", "--quiet")

    def redeploy(self) -> None:
        if self.context.clean:
            self.cleanup()
        if self.context.build_images:
            self._build_images()
        self._prepare_runtime_files()
        support_services = (
            "postgresql",
            "redis",
            "keycloak",
            "ldap",
            "jaeger",
            "mock-idp",
            "anvil",
            "solana",
        )
        self._compose("up", "-d", *support_services)
        self._wait_for_support_services()
        (self.runtime_dir / "authguard.yaml").write_text(
            self._authguard_runtime_config() + "\n", encoding="utf-8"
        )
        self._compose("up", "-d", "--remove-orphans")
        self._wait_for_runtime_services()

    def cleanup(self) -> None:
        if not self.compose_file.is_file():
            return
        if not self.runtime_dir.exists():
            self._prepare_runtime_files()
        self._compose(
            "down",
            "--volumes",
            "--remove-orphans",
            "--timeout",
            "15",
            allowed_codes={0, 1},
        )
        if self.runtime_dir.exists():
            try:
                shutil.rmtree(self.runtime_dir)
            except PermissionError:
                expected = (E2E_DIR / ".runtime" / "docker").resolve()
                if self.runtime_dir.resolve() != expected:
                    raise RuntimeError(
                        f"refusing privileged cleanup outside {expected}"
                    )
                self._run(
                    (
                        "docker",
                        "run",
                        "--rm",
                        "--user",
                        "0",
                        "-v",
                        f"{self.runtime_dir}:/runtime",
                        "--entrypoint",
                        "/bin/bash",
                        ALIYUN_POSTGRES_IMAGE,
                        "-ec",
                        "find /runtime -mindepth 1 -delete",
                    )
                )
                shutil.rmtree(self.runtime_dir)
        self._published_ports.clear()

    @contextmanager
    def _forward_service(self, service: str, remote_port: int) -> Iterator[int]:
        key = (service, remote_port)
        port = self._published_ports.get(key)
        if port is None:
            result = self._compose("port", service, str(remote_port))
            endpoint = result.output.strip().splitlines()[-1]
            try:
                port = int(endpoint.rsplit(":", 1)[1])
            except (IndexError, ValueError) as failure:
                raise RuntimeError(
                    f"Docker Compose returned an invalid port for {service}:{remote_port}: "
                    f"{endpoint!r}"
                ) from failure
            self._published_ports[key] = port
        yield port

    @contextmanager
    def _forward_envoy_admin(self) -> Iterator[int]:
        with self._forward_service("envoy", 19000) as port:
            yield port

    def _envoy_proxy_service(self) -> str:
        return "envoy"

    def service_logs(self, service: str, tail: int = 5000) -> str:
        output = self._compose(
            "logs", "--no-color", f"--tail={tail}", service
        ).output
        records: list[str] = []
        for line in output.splitlines():
            if line.startswith("Attaching to "):
                continue
            # Compose prefixes each record with `<service>_1 |`; verifiers
            # consume the application's actual JSON/log line on both backends.
            records.append(line.split(" | ", 1)[1] if " | " in line else line)
        return "\n".join(records)

    def postgresql_query(self, sql: str) -> str:
        return self._compose(
            "exec",
            "-T",
            "postgresql",
            "bash",
            "-ec",
            'PGPASSWORD="$POSTGRESQL_POSTGRES_PASSWORD" '
            'PGOPTIONS="-c search_path=authguard" psql '
            '-U postgres -d "$POSTGRESQL_DATABASE" -At '
            '--set=ON_ERROR_STOP=1 --command "$1"',
            "e2e-authguard-query",
            sql,
        ).output.strip()

    def verify_infrastructure_contract(self) -> None:
        """Verify Docker owns the same real services and trust boundaries as Helm."""
        expected_services = {
            "postgresql",
            "redis",
            "keycloak",
            "ldap",
            "jaeger",
            "mock-idp",
            "anvil",
            "solana",
            "authz",
            "authn",
            "web",
            "envoy",
            *WORKLOAD_IMAGES,
        }
        # Compose v1 lacks `ps --format json`. Collect its container IDs and
        # inspect them in one backend-neutral Docker API call instead. The ID
        # regex also ignores Podman's ANSI-colored compose-provider notice.
        container_ids = re.findall(
            r"(?m)(?:^|\x1b\[0m)([0-9a-f]{12,64})$",
            self._compose("ps", "-q").output,
        )
        if not container_ids:
            raise RuntimeError("Docker Compose returned no E2E containers")
        containers = json.loads(
            self._run(("docker", "inspect", *container_ids)).output
        )
        by_service = {
            container.get("Config", {})
            .get("Labels", {})
            .get("com.docker.compose.service"): container
            for container in containers
        }
        if missing := expected_services - set(by_service):
            raise RuntimeError(f"Docker E2E services are missing: {sorted(missing)}")
        not_running = {
            service: by_service[service].get("State", {}).get("Status")
            for service in expected_services
            if by_service[service].get("State", {}).get("Status") != "running"
        }
        if not_running:
            raise RuntimeError(f"Docker E2E services are not running: {not_running}")
        restarted = {
            service: int(by_service[service].get("RestartCount", 0))
            for service in expected_services
        }
        if failures := {name: count for name, count in restarted.items() if count}:
            raise RuntimeError(f"Docker E2E containers restarted: {failures}")
        web = by_service["web"]
        destinations = {mount["Destination"] for mount in web.get("Mounts", [])}
        theme_path = "/usr/share/nginx/html/assets/themes/custom"
        if theme_path not in destinations:
            raise RuntimeError(
                "Docker Web container does not mount the local theme directory"
            )
        for service in ("authn", "authz"):
            inspected = by_service[service]
            if theme_path in {
                mount["Destination"] for mount in inspected.get("Mounts", [])
            }:
                raise RuntimeError(f"theme assets leaked into Docker service {service}")
        if self.json_rpc("anvil", 8545, "eth_chainId") != hex(31337):
            raise RuntimeError("Docker Anvil did not expose chain 31337")
        if self.json_rpc("solana", 8899, "getHealth") != "ok":
            raise RuntimeError("Docker Solana test validator is unhealthy")
        self.details.append(
            "Docker Compose runs the real identity stores, local chains, AuthGuard, Envoy, "
            "and five business services; the local custom theme is mounted only into Web"
        )

    def _prepare_runtime_files(self) -> None:
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        (self.runtime_dir / "authguard.yaml").write_text("# rendered after support startup\n")
        self._write_authguard_environment()
        self._write_keycloak_realm()
        self._write_ldap_config()
        postgres_init = self.runtime_dir / "postgres-init.sh"
        postgres_init.write_text(self._postgres_init_script(), encoding="utf-8")
        postgres_init.chmod(0o755)

    def _write_authguard_environment(self) -> None:
        signing_key = (CONFIG_DIR / "e2e-jwt-keys/realm-signing-key.pem").read_bytes()
        resign_key = (CONFIG_DIR / "e2e-jwt-keys/resign-jwt-key.pem").read_bytes()
        values = {
            "AUTHGUARD__AUTHN__PROVIDERS__E2E_AUTHGUARD_KEYCLOAK__CLIENT_SECRET": "e2e-authguard-principal-discovery-client-secret",
            "AUTHGUARD__AUTHZ__PRINCIPAL_DISCOVERY__KEYCLOAK__INDEX_0__AUTH__CLIENT_SECRET": "e2e-authguard-principal-discovery-client-secret",
            "AUTHGUARD__AUTHZ__PRINCIPAL_DISCOVERY__LDAP__INDEX_0__AUTH__BIND_PASSWORD": "e2e-authguard-ldap-bind-password",
            "AUTHGUARD__AUTHN__PROVIDERS__GITHUB__CLIENT_SECRET": "e2e-authguard-github-secret",
            "AUTHGUARD__AUTHN__PROVIDERS__GOOGLE__CLIENT_SECRET": "e2e-authguard-google-secret",
            "AUTHGUARD__AUTHN__PROVIDERS__WECHAT__CLIENT_SECRET": "e2e-authguard-wechat-secret",
            "AUTHGUARD__AUTHN__PROVIDERS__QQ__CLIENT_SECRET": "e2e-authguard-qq-secret",
            "AUTHGUARD__AUTHN__STANDALONE__CREDENTIAL_ENCRYPTION_KEY": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
            "AUTHGUARD__STORAGE__POSTGRES__PASSWORD": "e2e-authguard-postgres-password",
            "AUTHGUARD__CACHE__REDIS__PASSWORD": "e2e-authguard-redis-password",
            "AUTHGUARD__AUTHZ__API__TOKEN": "e2e-authguard-api-token",
            "AUTHGUARD__AUTHZ__SCOPE_DELIVERY__DIRECT_CONTEXT_HMAC_KEY": "e2e-authguard-access-context-hmac-key",
            "AUTHGUARD__AUTHN__TOKEN__PRIVATE_KEY_B64": base64.b64encode(
                signing_key
            ).decode(),
            "AUTHGUARD__AUTHZ__RESIGN__PRIVATE_KEY_B64": base64.b64encode(
                resign_key
            ).decode(),
        }
        content = "".join(f"{key}={value}\n" for key, value in values.items())
        target = self.runtime_dir / "authguard.env"
        target.write_text(content, encoding="utf-8")
        target.chmod(0o600)

    def _write_keycloak_realm(self) -> None:
        source = json.loads(
            (CONFIG_DIR / "keycloak-realm.json").read_text(encoding="utf-8")
        )
        replacements = {
            "${E2E_AUTHGUARD_REALM_SIGNING_PRIVATE_KEY}": (
                CONFIG_DIR / "e2e-jwt-keys/realm-signing-key.pem"
            ).read_text(encoding="utf-8"),
            "${E2E_AUTHGUARD_REALM_SIGNING_CERTIFICATE}": (
                CONFIG_DIR / "e2e-jwt-keys/realm-signing-cert.pem"
            ).read_text(encoding="utf-8"),
            "${E2E_AUTHGUARD_PRINCIPAL_DISCOVERY_CLIENT_SECRET}": "e2e-authguard-principal-discovery-client-secret",
            "${E2E_AUTHGUARD_WORKLOAD_CLIENT_SECRET}": "e2e-authguard-workload-client-secret",
        }

        def replace(value: object) -> object:
            if isinstance(value, str):
                for marker, replacement in replacements.items():
                    value = value.replace(marker, replacement)
                return value
            if isinstance(value, list):
                return [replace(item) for item in value]
            if isinstance(value, dict):
                return {key: replace(item) for key, item in value.items()}
            return value

        (self.runtime_dir / "keycloak-realm.json").write_text(
            json.dumps(replace(source), indent=2) + "\n", encoding="utf-8"
        )

    def _write_ldap_config(self) -> None:
        bind_hash = hashlib.sha256(
            b"e2e-authguard-ldap-bind-password"
        ).hexdigest()
        (self.runtime_dir / "ldap-config.cfg").write_text(
            """[ldap]
  enabled = true
  listen = "0.0.0.0:389"

[ldaps]
  enabled = false

[behaviors]
  IgnoreCapabilities = true

[backend]
  datastore = "config"
  baseDN = "dc=example,dc=org"
  nameformat = "cn"
  groupformat = "ou"

[[users]]
  name = "svc-authguard"
  givenname = "Authguard"
  sn = "Principal Discovery"
  mail = "svc-authguard@example-corp.example"
  uidnumber = 5001
  primarygroup = 5500
  passsha256 = """ + json.dumps(bind_hash) + """
  othergroups = []

[[users]]
  name = "ldap-retention-analyst"
  givenname = "LDAP Retention"
  sn = "Analyst"
  mail = "ldap-retention-analyst@example-corp.example"
  uidnumber = 1001
  primarygroup = 5501
  passsha256 = "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"
  othergroups = [5501]
  [[users.customattributes]]
    displayName = ["LDAP Retention Analyst"]
    department = ["Customer Growth"]

[[groups]]
  name = "Users"
  gidnumber = 5500
  description = "LDAP service accounts"

[[groups]]
  name = "customer-growth-analysts"
  gidnumber = 5501
  description = "Customer growth analytics team"
""",
            encoding="utf-8",
        )

    @staticmethod
    def _postgres_init_script() -> str:
        roles = {
            "e2e_authguard_service": ("e2e-authguard-postgres-password", "authguard"),
            "e2e_authguard_customer_growth_go_sqlx": ("e2e-authguard-customer-growth-go-sqlx-password", "e2e_authguard_customer_growth_go_sqlx"),
            "e2e_authguard_customer_growth_rust_sqlx": ("e2e-authguard-customer-growth-rust-sqlx-password", "e2e_authguard_customer_growth_rust_sqlx"),
            "e2e_authguard_customer_growth_python_sqlalchemy": ("e2e-authguard-customer-growth-python-sqlalchemy-password", "e2e_authguard_customer_growth_python_sqlalchemy"),
            "e2e_authguard_customer_growth_spring_jdbc": ("e2e-authguard-customer-growth-spring-jdbc-password", "e2e_authguard_customer_growth_spring_jdbc"),
            "e2e_authguard_customer_growth_spring_jpa": ("e2e-authguard-customer-growth-spring-jpa-password", "e2e_authguard_customer_growth_spring_jpa"),
        }
        lines = [
            "#!/bin/bash",
            "set -euo pipefail",
            'export PGPASSWORD="$POSTGRESQL_POSTGRES_PASSWORD"',
        ]
        for role, (password, schema) in roles.items():
            lines.extend(
                (
                    "psql --host=127.0.0.1 --username=postgres --dbname=\"$POSTGRESQL_DATABASE\" "
                    f"--set=ON_ERROR_STOP=1 --set=role_name='{role}' "
                    f"--set=role_password='{password}' --set=schema_name='{schema}' <<'SQL'",
                    "SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'role_name', :'role_password') WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role_name') \\gexec",
                    "SELECT format('CREATE SCHEMA IF NOT EXISTS %I AUTHORIZATION %I', :'schema_name', :'role_name') \\gexec",
                    "SELECT format('ALTER ROLE %I IN DATABASE %I SET search_path = %I', :'role_name', current_database(), :'schema_name') \\gexec",
                    "SQL",
                )
            )
            if schema != "authguard":
                lines.append(
                    f"PGPASSWORD='{password}' PGOPTIONS='-c search_path={schema}' psql "
                    f"--host=127.0.0.1 --username='{role}' --dbname=\"$POSTGRESQL_DATABASE\" "
                    "--set=ON_ERROR_STOP=1 --file=/e2e-authguard-fixture/init.sql"
                )
        return "\n".join(lines) + "\n"

    def _wait_for_support_services(self) -> None:
        for service, port in (
            ("postgresql", 5432),
            ("redis", 6379),
            ("keycloak", 8080),
            ("ldap", 389),
            ("jaeger", 16686),
            ("mock-idp", 8080),
            ("anvil", 8545),
            ("solana", 8899),
        ):
            self._wait_for_tcp(service, port)
        self._wait_for_http("keycloak", 8080, "/realms/example-corp/.well-known/openid-configuration")
        self._wait_for_http("mock-idp", 8080, "/healthz")
        self._wait_for_json_rpc("anvil", 8545, "eth_chainId")
        self._wait_for_json_rpc("solana", 8899, "getHealth")

    def _wait_for_runtime_services(self) -> None:
        self._wait_for_http("authn", 9091, "/healthz")
        self._wait_for_http("authz", 9091, "/healthz")
        self._wait_for_http("web", 8080, "/auth/login")
        for service in WORKLOAD_IMAGES:
            self._wait_for_http(service, 8080, "/healthz")
        self._wait_for_tcp("envoy", 8082)

    def _wait_for_tcp(self, service: str, remote_port: int) -> None:
        deadline = time.monotonic() + self.context.timeout_seconds
        last_error = "not published"
        while time.monotonic() < deadline:
            try:
                with self._forward_service(service, remote_port) as port:
                    with socket.create_connection(("127.0.0.1", port), timeout=1):
                        return
            except (OSError, RuntimeError) as failure:
                last_error = str(failure)
                time.sleep(1)
        raise RuntimeError(f"timed out waiting for Docker service {service}: {last_error}")

    def _wait_for_http(self, service: str, remote_port: int, path: str) -> None:
        deadline = time.monotonic() + self.context.timeout_seconds
        last_error = "not available"
        while time.monotonic() < deadline:
            try:
                with self._forward_service(service, remote_port) as port:
                    with request.urlopen(
                        f"http://127.0.0.1:{port}{path}", timeout=3
                    ) as response:
                        if response.status < 500:
                            return
            except (error.URLError, OSError, RuntimeError) as failure:
                last_error = str(failure)
                time.sleep(1)
        raise RuntimeError(
            f"timed out waiting for Docker HTTP service {service}{path}: {last_error}"
        )

    def _wait_for_json_rpc(self, service: str, remote_port: int, method: str) -> None:
        deadline = time.monotonic() + self.context.timeout_seconds
        last_error = "not available"
        while time.monotonic() < deadline:
            try:
                self.json_rpc(service, remote_port, method)
                return
            except (error.URLError, OSError, RuntimeError) as failure:
                last_error = str(failure)
                time.sleep(1)
        raise RuntimeError(
            f"timed out waiting for Docker JSON-RPC {service}.{method}: {last_error}"
        )

    def _compose_container_id(self, service: str) -> str:
        container_id = self._compose("ps", "-q", service).output.strip()
        if not container_id:
            raise RuntimeError(f"Docker Compose service has no container: {service}")
        return container_id

    def _compose(
        self,
        *arguments: str,
        allowed_codes: set[int] | None = None,
    ):
        result = self._run(
            (
                "docker",
                "compose",
                "-p",
                self.project_name,
                "-f",
                str(self.compose_file),
                *arguments,
            ),
            cwd=E2E_DIR,
            allowed_codes=allowed_codes,
        )
        # Podman's Docker-compatible CLI prints an ANSI-colored provider
        # notice before every external docker-compose v1 response. Keep the
        # raw CommandResult in evidence, but expose only command payload to
        # callers that parse ports, JSON, SQL rows, or service IDs.
        output = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
        output = "\n".join(
            line
            for line in output.splitlines()
            if not line.startswith(">>>> Executing external compose provider ")
        ).strip()
        return replace(result, output=output)
