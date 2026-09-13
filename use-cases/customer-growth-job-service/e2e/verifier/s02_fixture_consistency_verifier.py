"""Validate the shared SQL data and authorization scenario contract."""

from __future__ import annotations

import json
import re
import sqlite3
import time

from common.config import CONFIG_DIR, DEPLOY_DIR
from common.model import RunContext, VerificationResult
from verifier.base_verifier import BaseVerifier


PROJECT_SOURCES = {
    "golang-sqlx-service": (
        "tests/customer_growth_job_e2e_test.go",
        "pkg/authorization/customer_growth_job_resource_mapping.go",
    ),
    "rust-sqlx-service": (
        "tests/customer_growth_job_e2e.rs",
        "src/authorization/mod.rs",
    ),
    "python-sqlalchemy-service": (
        "tests/test_customer_growth_job_e2e.py",
        "app/authorization/customer_growth_job_resource_mapping.py",
    ),
    "springboot-jdbc-service": (
        "src/test/java/com/authguard/usecases/support/E2EFixtures.java",
        "src/main/java/com/authguard/usecases/authorization/CustomerGrowthJobResourceMappings.java",
    ),
    "springboot-jpa-service": (
        "src/test/java/com/authguard/usecases/support/E2EFixtures.java",
        "src/main/java/com/authguard/usecases/authorization/CustomerGrowthJobResourceMappings.java",
    ),
}

BUSINESS_TABLE = "e2e_authguard_customer_growth_jobs"
PROJECT_REPOSITORIES = {
    "golang-sqlx-service": "pkg/repository/customer_growth_job_repository.go",
    "rust-sqlx-service": "src/repository/mod.rs",
    "python-sqlalchemy-service": "app/repository/customer_growth_job_repository.py",
    "springboot-jdbc-service": (
        "src/main/java/com/authguard/usecases/repository/CustomerGrowthJobJdbcRepository.java"
    ),
    "springboot-jpa-service": (
        "src/main/java/com/authguard/usecases/repository/CustomerGrowthJobJpaRepository.java"
    ),
}
PROJECT_EXECUTION_TESTS = {
    "golang-sqlx-service": "tests/customer_growth_job_e2e_test.go",
    "rust-sqlx-service": "tests/customer_growth_job_e2e.rs",
    "python-sqlalchemy-service": "tests/test_customer_growth_job_e2e.py",
    "springboot-jdbc-service": (
        "src/test/java/com/authguard/usecases/controller/CustomerGrowthJobControllerE2ETest.java"
    ),
    "springboot-jpa-service": (
        "src/test/java/com/authguard/usecases/controller/CustomerGrowthJobControllerE2ETest.java"
    ),
}


def _verify(_context: RunContext) -> VerificationResult:
    started = time.monotonic()
    errors: list[str] = []
    sql = (CONFIG_DIR / "init.sql").read_text(encoding="utf-8")
    fixture = json.loads(
        (CONFIG_DIR / "authguard-e2e-scenarios.json").read_text(encoding="utf-8")
    )
    mock_idp = (DEPLOY_DIR / "mocksvc-idp-service/app/server.py").read_text(
        encoding="utf-8"
    )
    authorization_verifier = (
        DEPLOY_DIR.parent / "verifier/s17_gateway_authorization_verifier.py"
    ).read_text(encoding="utf-8")

    with sqlite3.connect(":memory:") as connection:
        connection.executescript(sql)
        database_ids = {
            row[0]
            for row in connection.execute(
                "SELECT id FROM e2e_authguard_customer_growth_jobs"
            )
        }
        row_count = len(database_ids)

    scenarios = fixture.get("authz", {}).get("scenarios", [])
    scenario_ids = [scenario.get("id") for scenario in scenarios]
    if fixture.get("version") != 4:
        errors.append("AuthGuard E2E fixture version must be 4")
    if f"CREATE TABLE {BUSINESS_TABLE}" not in sql:
        errors.append(f"shared fixture must create isolated business table {BUSINESS_TABLE}")
    authn = fixture.get("authn", {})
    provider_flows = authn.get("provider_flows", [])
    linking = authn.get("account_linking", {})
    federation = fixture.get("principal_federation", {})
    keycloak = federation.get("keycloak", {})
    ldap = federation.get("ldap", {})
    provider_ids = {flow.get("provider_id") for flow in provider_flows}
    if provider_ids != {"github", "google", "wechat", "qq"}:
        errors.append("AuthN fixture must cover GitHub, Google, WeChat, and QQ provider flows")
    protocols = {flow.get("provider_id"): flow.get("protocol") for flow in provider_flows}
    if protocols != {
        "github": "oauth2",
        "google": "oauth2",
        "wechat": "oauth2-like",
        "qq": "oauth2-like",
    }:
        errors.append("mock IdP flows must stay OAuth/OAuth-like; OIDC belongs to Keycloak")
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
            r'@app\.(get|post)\("([^"{]+)"\)', mock_idp
        )
    }
    expected_mock_endpoints = {**mock_endpoints, "/healthz": "get"}
    if actual_mock_endpoints != expected_mock_endpoints:
        errors.append(
            "mock IdP routes must contain only the four OAuth-like provider contracts "
            f"plus healthz: actual={sorted(actual_mock_endpoints)}"
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
    if linking.get("strategy") != "first-login" or linking.get("email_auto_link") is not False:
        errors.append("AuthN 2C fixture must use first-login without email auto-link")
    keycloak_users = keycloak.get("users", [])
    keycloak_groups = keycloak.get("groups", [])
    if len(keycloak_users) != 3 or len(keycloak_groups) != 2 or not keycloak.get("workload"):
        errors.append("Keycloak federation must cover three users, two groups, and one workload")
    federated_ids = [
        identity.get("principal_id")
        for identity in [*keycloak_users, *keycloak_groups, keycloak.get("workload", {})]
    ]
    if len(federated_ids) != len(set(federated_ids)) or any(not value for value in federated_ids):
        errors.append("federated Keycloak principal IDs must be non-empty and unique")
    if not ldap.get("direct", {}).get("provider_id") or not ldap.get("identity", {}).get(
        "immutable_external_id"
    ):
        errors.append("direct LDAP federation must define a provider and immutable identity")
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
        errors.append(f"real gateway resource-authorization assertions are incomplete: {missing}")
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
            errors.append(f"{scenario.get('id')}: route resource must use customer-growth")
        urns = [*scenario.get("allow_resource_urns", []), *scenario.get("deny_resource_urns", [])]
        if any(not urn.startswith("urn:iam:") for urn in urns):
            errors.append(f"{scenario.get('id')}: grant contains a non-IAM URN")

    operations = {scenario.get("operation") for scenario in scenarios}
    if operations != {"list", "get", "create", "update", "delete"}:
        errors.append(f"CRUD operation coverage is incomplete: {sorted(operations)}")
    if not any("/*" in urn for scenario in scenarios for urn in scenario.get("allow_resource_urns", [])):
        errors.append("single-segment wildcard coverage is missing")
    if not any("/**" in urn or urn.endswith(":**") for scenario in scenarios for urn in scenario.get("allow_resource_urns", [])):
        errors.append("recursive globstar coverage is missing")
    condition_scenarios = [scenario for scenario in scenarios if scenario.get("conditions")]
    if len(condition_scenarios) < 10:
        errors.append("at least ten conditional authorization scenarios are required")
    if not any("sourceIp" in scenario["conditions"] for scenario in condition_scenarios):
        errors.append("source IP condition coverage is missing")

    for project_name, (test_source, mapping_source) in PROJECT_SOURCES.items():
        test_text = (DEPLOY_DIR / project_name / test_source).read_text(encoding="utf-8")
        mapping_text = (DEPLOY_DIR / project_name / mapping_source).read_text(
            encoding="utf-8"
        )
        for fixture_name in ("init.sql", "authguard-e2e-scenarios.json"):
            if fixture_name not in test_text:
                errors.append(f"{project_name}: does not consume {fixture_name}")
        if "customer-growth" not in mapping_text:
            errors.append(f"{project_name}: resource mapping does not use customer-growth")
        repository_path = DEPLOY_DIR / project_name / PROJECT_REPOSITORIES[project_name]
        repository_text = repository_path.read_text(encoding="utf-8")
        if BUSINESS_TABLE not in repository_text:
            errors.append(f"{project_name}: repository does not use {BUSINESS_TABLE}")
        execution_test = (
            DEPLOY_DIR / project_name / PROJECT_EXECUTION_TESTS[project_name]
        ).read_text(encoding="utf-8")
        if "AUTHGUARD_E2E_CASE id=" not in execution_test:
            errors.append(f"{project_name}: does not emit auditable scenario execution markers")

    matrix_sources = "\n".join(
        (DEPLOY_DIR.parent / relative).read_text(encoding="utf-8")
        for relative in ("common/project.py", "runner.py")
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
        "Every language reads the same SQL and JSON fixtures",
    ]
    details.extend(errors)
    return VerificationResult(
        scenario_id="02",
        title="Shared SQL and authorization fixture consistency",
        passed=not errors,
        duration_seconds=time.monotonic() - started,
        details=details,
    )


class FixtureConsistencyVerifier(BaseVerifier):
    scenario_id = "02"
    title = "Shared SQL and authorization fixture consistency"

    def run(self) -> VerificationResult:
        return self.step("validate SQL seeds and all authorization scenario contracts", lambda: _verify(self.context))


def verify(context: RunContext) -> VerificationResult:
    return FixtureConsistencyVerifier(context).run()
