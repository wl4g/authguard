"""Static paths and project commands for the portable E2E suite."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import sys
from urllib.parse import urlparse


E2E_DIR = Path(__file__).resolve().parents[1]
USE_CASE_DIR = E2E_DIR.parent
PROJECT_ROOT = USE_CASE_DIR.parents[1]
CONFIG_DIR = E2E_DIR / "config"
AUTHGUARD_CONFIG_DIR = CONFIG_DIR / "authguard"
AUTHGUARD_INIT_SQL_PATH = AUTHGUARD_CONFIG_DIR / "e2e-init.sql"
AUTHGUARD_SCENARIOS_PATH = AUTHGUARD_CONFIG_DIR / "e2e-scenarios.json"
AUTHGUARD_JWT_KEYS_DIR = AUTHGUARD_CONFIG_DIR / "e2e-jwt-keys"
KEYCLOAK_CONFIG_DIR = CONFIG_DIR / "keycloak"
KEYCLOAK_REALM_PATH = KEYCLOAK_CONFIG_DIR / "e2e-realm.json"
DEPLOY_DIR = E2E_DIR / "deploy"
REPORTS_DIR = E2E_DIR / "reports"
ADAPTERS_DIR = PROJECT_ROOT / "src" / "adapters"


@dataclass(frozen=True)
class ProjectSpec:
    name: str
    title: str
    path: Path
    setup_commands: tuple[tuple[str, ...], ...]
    clean_commands: tuple[tuple[str, ...], ...]
    test_command: tuple[str, ...]
    environment: dict[str, str]


JAVA_ADAPTER_INSTALL = (
    "mvn",
    "-q",
    "-f",
    str(ADAPTERS_DIR / "java" / "pom.xml"),
    "-DskipTests",
    "install",
)

PYTHON_SERVICE = DEPLOY_DIR / "biz-python-sqlalchemy-service"


def _maven_environment() -> dict[str, str]:
    proxy = os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY")
    if not proxy:
        return {}
    parsed = urlparse(proxy)
    if not parsed.hostname or not parsed.port:
        raise ValueError("HTTPS_PROXY/HTTP_PROXY must include a host and port")
    proxy_options = " ".join(
        f"-D{protocol}.proxyHost={parsed.hostname} -D{protocol}.proxyPort={parsed.port}"
        for protocol in ("http", "https")
    )
    return {"MAVEN_OPTS": f"{os.getenv('MAVEN_OPTS', '')} {proxy_options}".strip()}


MAVEN_ENVIRONMENT = _maven_environment()

PROJECTS = {
    "biz-golang-sqlx-service": ProjectSpec(
        name="biz-golang-sqlx-service",
        title="Go + sqlx + SQLite",
        path=DEPLOY_DIR / "biz-golang-sqlx-service",
        setup_commands=(),
        clean_commands=(("go", "clean", "-testcache"),),
        test_command=("go", "test", "-count=1", "-v", "./..."),
        environment={"GOPROXY": os.environ.get("GOPROXY", "https://goproxy.cn,direct")},
    ),
    "biz-rust-sqlx-service": ProjectSpec(
        name="biz-rust-sqlx-service",
        title="Rust + sqlx + SQLite",
        path=DEPLOY_DIR / "biz-rust-sqlx-service",
        setup_commands=(),
        clean_commands=(
            ("cargo", "clean", "-p", "authguard-customer-growth-job-rust-service"),
        ),
        test_command=(
            "cargo",
            "test",
            "-p",
            "authguard-customer-growth-job-rust-service",
            "--test",
            "customer_growth_job_e2e",
            "--",
            "--nocapture",
        ),
        environment={},
    ),
    "biz-python-sqlalchemy-service": ProjectSpec(
        name="biz-python-sqlalchemy-service",
        title="Python + SQLAlchemy + SQLite",
        path=PYTHON_SERVICE,
        setup_commands=(),
        clean_commands=(),
        test_command=(
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-v",
        ),
        environment={
            "PYTHONPATH": os.pathsep.join(
                [str(ADAPTERS_DIR / "python"), str(PYTHON_SERVICE)]
            )
        },
    ),
    "biz-springboot-jdbc-service": ProjectSpec(
        name="biz-springboot-jdbc-service",
        title="Spring Boot + JDBC + SQLite",
        path=DEPLOY_DIR / "biz-springboot-jdbc-service",
        setup_commands=(JAVA_ADAPTER_INSTALL,),
        clean_commands=(("mvn", "-q", "clean"),),
        test_command=("mvn", "-q", "test"),
        environment=MAVEN_ENVIRONMENT,
    ),
    "biz-springboot-jpa-service": ProjectSpec(
        name="biz-springboot-jpa-service",
        title="Spring Boot + JPA + H2",
        path=DEPLOY_DIR / "biz-springboot-jpa-service",
        setup_commands=(JAVA_ADAPTER_INSTALL,),
        clean_commands=(("mvn", "-q", "clean"),),
        test_command=("mvn", "-q", "test"),
        environment=MAVEN_ENVIRONMENT,
    ),
}

DEFAULT_SCENARIOS = {
    "01": (
        "Use-case structure and project boundaries",
        "verifier.infra.s01_structure",
    ),
    "02": (
        "Shared SQL and authorization fixture consistency",
        "verifier.infra.s02_fixture_consistency",
    ),
    "03": (
        "Cross-language adapter contract parity",
        "verifier.infra.s03_adapter_contract",
    ),
    "21": (
        PROJECTS["biz-golang-sqlx-service"].title,
        "verifier.authz.sdk-golang.s21_sqlx",
    ),
    "22": (
        PROJECTS["biz-rust-sqlx-service"].title,
        "verifier.authz.sdk-rust.s22_sqlx",
    ),
    "23": (
        PROJECTS["biz-python-sqlalchemy-service"].title,
        "verifier.authz.sdk-python.s23_sqlalchemy",
    ),
    "24": (
        PROJECTS["biz-springboot-jdbc-service"].title,
        "verifier.authz.sdk-java.s24_springboot_jdbc",
    ),
    "25": (
        PROJECTS["biz-springboot-jpa-service"].title,
        "verifier.authz.sdk-java.s25_springboot_jpa",
    ),
}

OPTIONAL_SCENARIOS = {
    "00": (
        "Infrastructure: deployment and middleware initialization",
        "verifier.infra.s00_infrastructure",
    ),
    "10": (
        "AuthN: unified OAuth/OIDC, standalone, WebAuthn, and CAIP/SIWX",
        "verifier.authn.other.s10_authentication",
    ),
    "20": (
        "AuthZ: federation and administrator pre-authorization",
        "verifier.authz.other.s20_principal_preauthorization",
    ),
    "26": (
        "AuthZ: OIDC user/workload, Envoy, PDP, and business CRUD",
        "verifier.authz.other.s26_gateway_authorization",
    ),
    "30": (
        "Web: real Chromium authentication and Dashboard journeys",
        "verifier.web.s30_authguard_ui",
    ),
    "31": (
        "Web: hosted login application branding and return-target safety",
        "verifier.web.s31_hosted_login",
    ),
    "40": (
        "Observability: PostgreSQL, logs, metrics, Jaeger, and runtime health",
        "verifier.jaeger.s40_runtime_evidence",
    ),
}

SCENARIOS = dict(sorted({**DEFAULT_SCENARIOS, **OPTIONAL_SCENARIOS}.items()))
