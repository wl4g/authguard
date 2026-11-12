"""Case topology, scenario data paths and execution definitions."""
from __future__ import annotations
from util.images import E2EImagesDefinitions
import os
from pathlib import Path


class E2EOtherDefinitions:
    WORKLOAD_DIRECTORIES = {
        "go-sqlx": "biz-golang-sqlx-service",
        "rust-sqlx": "biz-rust-sqlx-service",
        "python-sqlalchemy": "biz-python-sqlalchemy-service",
        "spring-jdbc": "biz-springboot-jdbc-service",
        "spring-jpa": "biz-springboot-jpa-service",
    }
    WORKLOAD_HOSTS = {
        component: f"e2e-authguard-{component}.customer-growth.local"
        for component in E2EImagesDefinitions.WORKLOADS
    }
    E2E_DIR = Path(__file__).resolve().parents[1]
    USE_CASE_DIR = E2E_DIR
    PROJECT_ROOT = USE_CASE_DIR.parents[1]
    DEPLOY_DIR = E2E_DIR / "deploy"
    AUTHGUARD_CONFIG_DIR = DEPLOY_DIR / "authguard" / "config"
    AUTHGUARD_INIT_SQL_PATH = DEPLOY_DIR / "postgresql" / "source" / "init.sql"
    SCENARIOS_PATH = E2E_DIR / "verifier" / "scenarios.json"
    AUTHGUARD_JWT_KEYS_DIR = AUTHGUARD_CONFIG_DIR / "jwt-keys"
    KEYCLOAK_CONFIG_DIR = DEPLOY_DIR / "keycloak" / "source"
    KEYCLOAK_REALM_PATH = KEYCLOAK_CONFIG_DIR / "realm.json"
    REPORTS_DIR = E2E_DIR / "reports"
    SCENARIOS = {
        "01": (
            "Use-case structure and project boundaries",
            "verifier.infra.s01_structure",
        ),
        "02": (
            "Shared SQL and authorization scenario data consistency",
            "verifier.infra.s02_scenario_data_consistency",
        ),
        "00": (
            "Infrastructure: deployment and middleware initialization",
            "verifier.infra.s00_infrastructure",
        ),
        "20": (
            "AuthZ: federation and administrator pre-authorization",
            "verifier.authz.s20_principal_preauthorization",
        ),
        "10": (
            "AuthN: unified OAuth/OIDC, standalone, WebAuthn, and CAIP/SIWX",
            "verifier.authn.s10_authentication",
        ),
        "26": (
            "AuthZ: OIDC user/workload, Envoy, PDP, and business CRUD",
            "verifier.authz.s26_gateway_authorization",
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
            "Observability: metrics and management diagnostics",
            "verifier.otel.s40_metrics",
        ),
        "41": (
            "Observability: tracing across AuthN, AuthZ and business services",
            "verifier.otel.s41_tracing",
        ),
        "42": (
            "Observability: structured AuthN, AuthZ and SDK logs",
            "verifier.otel.s42_logs",
        ),
    }
    DEFAULT_SCENARIOS = tuple(SCENARIOS)
    COMPONENTS = {
        "authguard": "authguard",
        "envoy_gateway": "envoy-gateway",
        "envoy": "envoy",
        "redis": "redis",
        "postgres": "postgresql",
        "keycloak": "keycloak",
        "ldap": "ldap",
        "jaeger": "jaeger",
        "mock-idp": "mock-external-idp-service",
        "anvil": "anvil",
        "solana": "solana",
        **WORKLOAD_DIRECTORIES,
    }
    SUPPORT_COMPONENTS = (
        "postgres",
        "keycloak",
        "ldap",
        "jaeger",
        "mock-idp",
        "anvil",
        "solana",
        *WORKLOAD_DIRECTORIES,
        "redis",
    )

    @classmethod
    def chart(cls, component: str) -> Path:
        return E2EOtherDefinitions.DEPLOY_DIR / cls.COMPONENTS[component] / "helm"

    @staticmethod
    def select(values: dict, component: str) -> dict:
        if component in E2EOtherDefinitions.WORKLOAD_DIRECTORIES:
            return {
                **{
                    key: values[key]
                    for key in (
                        "support",
                        "authguard",
                        "postgresql",
                        "gateway",
                        "customerGrowth",
                    )
                },
                "workloads": {component: values["workloads"][component]},
            }
        keys = {
            "authguard": ("support", "global", "authguard", "authguard-middleware"),
            "postgres": ("support", "postgresql", "workloads"),
            "keycloak": ("support", "keycloak"),
            "ldap": ("support", "ldap"),
            "jaeger": ("support", "jaeger"),
            "mock-idp": ("support", "mockIdp"),
            "anvil": ("support", "anvil"),
            "solana": ("support", "solana"),
            "redis": ("redis_cluster",),
            "envoy_gateway": ("envoy_gateway",),
            "envoy": ("image", "config", "authnService", "authzService", "webService"),
        }[component]
        selected = {key: values[key] for key in keys if key in values}
        if component == "authguard" and values.get("support", {}).get("enabled", False):
            selected["keycloak"] = {
                key: values["keycloak"][key]
                for key in ("realmSigningPrivateKey", "resignJwtPrivateKey")
            }
            selected["postgresql"] = {
                "authguardPassword": values["postgresql"]["authguardPassword"]
            }
        return selected

    @classmethod
    def values(cls, environment=None) -> dict:
        import yaml

        values = {}
        for directory in cls.COMPONENTS.values():
            own = (
                yaml.safe_load(
                    (
                        E2EOtherDefinitions.DEPLOY_DIR / directory / "helm/values.yaml"
                    ).read_text()
                )
                or {}
            )
            cls.merge(values, own)
        values["keycloak"][
            "realm"
        ] = E2EOtherDefinitions.KEYCLOAK_REALM_PATH.read_text()
        keys = {
            "realmSigningPrivateKey": "realm-signing-key.pem",
            "realmSigningCertificate": "realm-signing-cert.pem",
            "realmSigningJwks": "realm-signing-jwk.json",
            "resignJwtPrivateKey": "resign-jwt-key.pem",
            "resignJwtPublicKey": "resign-jwt-key.pub.pem",
        }
        values["keycloak"].update(
            {
                name: (E2EOtherDefinitions.AUTHGUARD_JWT_KEYS_DIR / file).read_text()
                for name, file in keys.items()
            }
        )
        values["postgresql"][
            "initSQL"
        ] = E2EOtherDefinitions.AUTHGUARD_INIT_SQL_PATH.read_text()
        values["ldap"]["config"] = (
            E2EOtherDefinitions.DEPLOY_DIR / "ldap/source/config.cfg"
        ).read_text()
        values["config"] = (
            E2EOtherDefinitions.DEPLOY_DIR / "envoy/source/envoy.yaml"
        ).read_text()
        values["authguard"]["grpcTarget"] = "authguard:8081"
        values["gateway"] = {"name": "gateway"}
        for path, image in E2EImagesDefinitions.helm_values(environment).items():
            cls.set_value(values, path, image)
        return values

    @classmethod
    def merge(cls, target: dict, source: dict) -> None:
        for key, value in source.items():
            if isinstance(value, dict) and isinstance(target.get(key), dict):
                cls.merge(target[key], value)
            else:
                target[key] = value

    @staticmethod
    def set_value(values: dict, path: str, value: str) -> None:
        keys = path.split(".")
        for key in keys[:-1]:
            values = values.setdefault(key, {})
        values[keys[-1]] = value

    AUTHGUARD_API_TOKEN = "e2e-authguard-api-token"
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

    @classmethod
    def management(cls) -> dict:
        import yaml

        config = yaml.safe_load((cls.PROJECT_ROOT / "etc/authguard.yaml").read_text())[
            "mgmt"
        ]
        port = int(config["port"])
        path = config["metrics"]["path"]
        if not 0 < port < 65536 or not path.startswith("/"):
            raise ValueError("invalid management endpoint in etc/authguard.yaml")
        return config
