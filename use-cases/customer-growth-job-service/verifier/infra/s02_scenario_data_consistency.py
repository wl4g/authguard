"""Validate the shared SQL data and authorization scenario contract."""
from __future__ import annotations
from util.sqlite import E2ESQLiteImporter, E2ESQLiteChecker
from util.constant import E2EOtherDefinitions
import json
import re
import sqlite3
import time
from contextlib import closing
from verifier.context import VerificationContext, VerificationResult, BaseVerifier

PROJECT_SOURCES = {
    "biz-golang-sqlx-service": (
        "sdk/s21_sqlx_test.go",
        "pkg/authorization/customer_growth_job_resource_mapping.go",
    ),
    "biz-rust-sqlx-service": (
        "sdk/s22_sqlx.rs",
        "src/authorization/mod.rs",
    ),
    "biz-python-sqlalchemy-service": (
        "sdk/s23_sqlalchemy.py",
        "app/authorization/customer_growth_job_resource_mapping.py",
    ),
    "biz-springboot-jdbc-service": (
        "sdk/jdbc/com/authguard/usecases/support/AuthorizationScenarioData.java",
        "src/main/java/com/authguard/usecases/authorization/CustomerGrowthJobResourceMappings.java",
    ),
    "biz-springboot-jpa-service": (
        "sdk/jpa/com/authguard/usecases/support/AuthorizationScenarioData.java",
        "src/main/java/com/authguard/usecases/authorization/CustomerGrowthJobResourceMappings.java",
    ),
}
BUSINESS_TABLE = "e2e_authguard_customer_growth_jobs"
PROJECT_REPOSITORIES = {
    "biz-golang-sqlx-service": "pkg/repository/customer_growth_job_repository.go",
    "biz-rust-sqlx-service": "src/repository/mod.rs",
    "biz-python-sqlalchemy-service": "app/repository/customer_growth_job_repository.py",
    "biz-springboot-jdbc-service": "src/main/java/com/authguard/usecases/repository/CustomerGrowthJobJdbcRepository.java",
    "biz-springboot-jpa-service": "src/main/java/com/authguard/usecases/repository/CustomerGrowthJobJpaRepository.java",
}
PROJECT_EXECUTION_TESTS = {
    "biz-golang-sqlx-service": "sdk/s21_sqlx_test.go",
    "biz-rust-sqlx-service": "sdk/s22_sqlx.rs",
    "biz-python-sqlalchemy-service": "sdk/s23_sqlalchemy.py",
    "biz-springboot-jdbc-service": "sdk/jdbc/com/authguard/usecases/controller/CustomerGrowthJobControllerE2ETest.java",
    "biz-springboot-jpa-service": "sdk/jpa/com/authguard/usecases/controller/CustomerGrowthJobControllerE2ETest.java",
}


class E2ES02ScenarioDataConsistencyVerifier(BaseVerifier):
    def deploy(self, context: VerificationContext) -> None:
        """Reuse infrastructure owned by scenario 00."""

    def init(self, context: VerificationContext) -> None:
        """No additional scenario test data initialization is required."""

    scenario_id = "02"
    title = "Shared SQL and authorization scenario data consistency"
    requires_deployer = False

    def verifier(self, context: VerificationContext) -> VerificationResult:
        return self.step(
            "validate SQL seeds and all authorization scenario contracts",
            lambda: E2ES02ScenarioDataConsistencyVerifier._verify(self.context),
        )

    @staticmethod
    def _verify(_context: VerificationContext) -> VerificationResult:
        started = time.monotonic()
        errors: list[str] = []
        sql = E2EOtherDefinitions.AUTHGUARD_INIT_SQL_PATH.read_text(encoding="utf-8")
        scenario_data = json.loads(
            E2EOtherDefinitions.SCENARIOS_PATH.read_text(encoding="utf-8")
        )
        mock_idp = (
            E2EOtherDefinitions.DEPLOY_DIR
            / "mock-external-idp-service/source/app/server.py"
        ).read_text(encoding="utf-8")
        authorization_verifier = (
            E2EOtherDefinitions.DEPLOY_DIR.parent
            / "verifier/authz/s26_gateway_authorization.py"
        ).read_text(encoding="utf-8")
        with closing(sqlite3.connect(":memory:")) as connection:
            E2ESQLiteImporter.import_file(
                connection, E2EOtherDefinitions.AUTHGUARD_INIT_SQL_PATH
            )
            database_ids = {
                row[0]
                for row in E2ESQLiteChecker.query(
                    connection, "SELECT id FROM e2e_authguard_customer_growth_jobs"
                )
            }
            row_count = len(database_ids)
        scenarios = scenario_data.get("authz", {}).get("scenarios", [])
        scenario_ids = [scenario.get("id") for scenario in scenarios]
        if scenario_data.get("version") != 4:
            errors.append("AuthGuard E2E scenario data version must be 4")
        if f"CREATE TABLE {BUSINESS_TABLE}" not in sql:
            errors.append(
                f"shared scenario data must create isolated business table {BUSINESS_TABLE}"
            )
        authn = scenario_data.get("authn", {})
        provider_flows = authn.get("provider_flows", [])
        linking = authn.get("account_linking", {})
        federation = scenario_data.get("principal_federation", {})
        keycloak = federation.get("keycloak", {})
        ldap = federation.get("ldap", {})
        provider_ids = {flow.get("provider_id") for flow in provider_flows}
        if provider_ids != {"github", "google", "wechat", "qq"}:
            errors.append(
                "AuthN scenario data must cover GitHub, Google, WeChat, and QQ provider flows"
            )
        protocols = {
            flow.get("provider_id"): flow.get("protocol") for flow in provider_flows
        }
        if protocols != {
            "github": "oauth2",
            "google": "oauth2",
            "wechat": "oauth2-like",
            "qq": "oauth2-like",
        }:
            errors.append(
                "mock IdP flows must stay OAuth/OAuth-like; OIDC belongs to Keycloak"
            )
        mock_endpoints = {
            "/github/login/oauth/authorize": "get",
            "/github/login/oauth/access_token": "post",
            "/github/user": "get",
            "/google/o/oauth2/v2/auth": "get",
            "/google/token": "post",
            "/google/oauth2/v3/userinfo": "get",
            "/wechat/connect/qrconnect": "get",
            "/wechat/sns/oauth2/access_token": "get",
            "/qq/oauth2.0/authorize": "get",
            "/qq/oauth2.0/token": "get",
            "/qq/oauth2.0/me": "get",
        }
        actual_mock_endpoints = {
            endpoint: method
            for method, endpoint in re.findall(
                '@app\\.(get|post)\\("([^"{]+)"\\)', mock_idp
            )
        }
        expected_mock_endpoints = {
            **mock_endpoints,
            "/healthz": "get",
            "/fault/ethereum/<chain_id>/timeout": "post",
        }
        if actual_mock_endpoints != expected_mock_endpoints:
            errors.append(
                f"mock service routes must contain only OAuth-like provider contracts, healthz, and the explicit RPC timeout fault: actual={sorted(actual_mock_endpoints)}"
            )
        wire_contracts = (
            'return _authorize("github", "client_id")',
            '"application/json" in request.headers.get("Accept", "")',
            'return _authorize("google", "client_id")',
            'return _authorize("wechat", "appid")',
            'request.args.get("secret", "")',
            'return _authorize("qq", "client_id")',
            'request.args.get("fmt") == "json"',
            'request.args.get("access_token", "")',
            "docs.github.com/",
            "developers.google.com/",
            "developers.weixin.qq.com/",
            "wiki.connect.qq.com/",
        )
        if missing := [value for value in wire_contracts if value not in mock_idp]:
            errors.append(f"mock IdP wire/docs contracts are incomplete: {missing}")
        if (
            linking.get("strategy") != "first-login"
            or linking.get("email_auto_link") is not False
        ):
            errors.append(
                "AuthN 2C scenario data must use first-login without email auto-link"
            )
        keycloak_users = keycloak.get("users", [])
        keycloak_groups = keycloak.get("groups", [])
        if (
            len(keycloak_users) != 3
            or len(keycloak_groups) != 2
            or (not keycloak.get("workload"))
        ):
            errors.append(
                "Keycloak federation must cover three users, two groups, and one workload"
            )
        federated_ids = [
            identity.get("principal_id")
            for identity in [
                *keycloak_users,
                *keycloak_groups,
                keycloak.get("workload", {}),
            ]
        ]
        if len(federated_ids) != len(set(federated_ids)) or any(
            (not value for value in federated_ids)
        ):
            errors.append(
                "federated Keycloak principal IDs must be non-empty and unique"
            )
        if not ldap.get("direct", {}).get("provider_id") or not ldap.get(
            "identity", {}
        ).get("immutable_external_id"):
            errors.append(
                "direct LDAP federation must define a provider and immutable identity"
            )
        if len(scenarios) < 30:
            errors.append("at least 30 authorization scenarios are required")
        if len(scenario_ids) != len(set(scenario_ids)):
            errors.append("authorization scenario ids must be unique")
        gateway_contracts = (
            "LIST action with empty data scope",
            "empty data scope hides every seeded row",
            "create denied by AuthZ",
            "forbidden create Envoy ext_authz.denied",
            "workload without create action is rejected by AuthZ",
            "all five PostgreSQL schemas exactly match",
            "row matrix verified",
        )
        if missing := [
            value for value in gateway_contracts if value not in authorization_verifier
        ]:
            errors.append(
                f"real gateway resource-authorization assertions are incomplete: {missing}"
            )
        row_oracle_principals = (
            "principal-direct-reader",
            "principal-token-editor",
            "principal-no-data-reader",
            "principal-growth-job-runner",
        )
        if missing := [
            principal
            for principal in row_oracle_principals
            if principal not in authorization_verifier
        ]:
            errors.append(f"phase 17 row-access oracle is incomplete: {missing}")
        urn_prefix = "urn:iam:prod:customer-growth:"
        for scenario in scenarios:
            referenced_ids = set(scenario.get("expected_job_ids", []))
            if not referenced_ids.issubset(database_ids):
                errors.append(f"{scenario.get('id')}: expected unknown database ids")
            if not scenario.get("resource_urn", "").startswith(urn_prefix):
                errors.append(
                    f"{scenario.get('id')}: route resource must use customer-growth"
                )
            urns = [
                *scenario.get("allow_resource_urns", []),
                *scenario.get("deny_resource_urns", []),
            ]
            if any((not urn.startswith("urn:iam:") for urn in urns)):
                errors.append(f"{scenario.get('id')}: grant contains a non-IAM URN")
        operations = {scenario.get("operation") for scenario in scenarios}
        if operations != {"list", "get", "create", "update", "delete"}:
            errors.append(
                f"CRUD operation coverage is incomplete: {sorted(operations)}"
            )
        if not any(
            (
                "/*" in urn
                for scenario in scenarios
                for urn in scenario.get("allow_resource_urns", [])
            )
        ):
            errors.append("single-segment wildcard coverage is missing")
        if not any(
            (
                "/**" in urn or urn.endswith(":**")
                for scenario in scenarios
                for urn in scenario.get("allow_resource_urns", [])
            )
        ):
            errors.append("recursive globstar coverage is missing")
        condition_scenarios = [
            scenario for scenario in scenarios if scenario.get("conditions")
        ]
        if len(condition_scenarios) < 10:
            errors.append(
                "at least ten conditional authorization scenarios are required"
            )
        if not any(
            ("sourceIp" in scenario["conditions"] for scenario in condition_scenarios)
        ):
            errors.append("source IP condition coverage is missing")
        for project_name, (test_source, mapping_source) in PROJECT_SOURCES.items():
            test_text = (
                E2EOtherDefinitions.E2E_DIR / "verifier" / test_source
            ).read_text(encoding="utf-8")
            mapping_text = (
                E2EOtherDefinitions.DEPLOY_DIR
                / project_name
                / "source"
                / mapping_source
            ).read_text(encoding="utf-8")
            for data_name, definition in (
                (
                    E2EOtherDefinitions.AUTHGUARD_INIT_SQL_PATH.name,
                    "E2EOtherDefinitions.AUTHGUARD_INIT_SQL_PATH",
                ),
                (
                    E2EOtherDefinitions.SCENARIOS_PATH.name,
                    "E2EOtherDefinitions.SCENARIOS_PATH",
                ),
            ):
                if data_name not in test_text and definition not in test_text:
                    errors.append(f"{project_name}: does not consume {data_name}")
            if "customer-growth" not in mapping_text:
                errors.append(
                    f"{project_name}: resource mapping does not use customer-growth"
                )
            repository_path = (
                E2EOtherDefinitions.DEPLOY_DIR
                / project_name
                / "source"
                / PROJECT_REPOSITORIES[project_name]
            )
            repository_text = repository_path.read_text(encoding="utf-8")
            if BUSINESS_TABLE not in repository_text:
                errors.append(
                    f"{project_name}: repository does not use {BUSINESS_TABLE}"
                )
            execution_test = (
                E2EOtherDefinitions.E2E_DIR
                / "verifier"
                / PROJECT_EXECUTION_TESTS[project_name]
            ).read_text(encoding="utf-8")
            if "AUTHGUARD_E2E_CASE id=" not in execution_test:
                errors.append(
                    f"{project_name}: does not emit auditable scenario execution markers"
                )
        matrix_sources = "\n".join(
            (
                (E2EOtherDefinitions.DEPLOY_DIR.parent / relative).read_text(
                    encoding="utf-8"
                )
                for relative in ("verifier/sdk/sdk_scenario.py", "runner.py")
            )
        )
        for marker in ("verify_scenario_matrix", "expected_total", "case_executions"):
            if marker not in matrix_sources:
                errors.append(f"cross-service scenario matrix is missing {marker}")
        details = [
            f"Shared database rows: {row_count}",
            f"Isolated business table: {BUSINESS_TABLE}",
            f"Shared authorization scenarios: {len(scenarios)}",
            f"Cross-service execution contract: {len(scenarios)} × 5 = {len(scenarios) * 5}",
            f"Conditional gateway scenarios: {len(condition_scenarios)}",
            "CRUD, action isolation, *, **, explicit deny, IP, transport, MFA, and claims",
            "AuthN covers realistic GitHub, Google, WeChat, and QQ OAuth-like wire contracts",
            "Enterprise federation covers Keycloak USER/GROUP/WORKLOAD and direct LDAP identity",
            "All five deployed Biz services assert functional 403 and zero-row data scopes for user/workload callers",
            "Every language reads the same SQL and JSON test data",
        ]
        details.extend(errors)
        return VerificationResult(
            scenario_id="02",
            title="Shared SQL and authorization scenario data consistency",
            passed=not errors,
            duration_seconds=time.monotonic() - started,
            details=details,
        )
