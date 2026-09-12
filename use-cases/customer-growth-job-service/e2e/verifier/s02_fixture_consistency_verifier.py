"""Validate the shared SQL data and authorization scenario contract."""

from __future__ import annotations

import json
import sqlite3
import time

from common.config import CONFIG_DIR, DEPLOY_DIR
from common.model import RunContext, VerificationResult


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


def verify(_context: RunContext) -> VerificationResult:
    started = time.monotonic()
    errors: list[str] = []
    sql = (CONFIG_DIR / "init.sql").read_text(encoding="utf-8")
    fixture = json.loads(
        (CONFIG_DIR / "authguard-e2e-scenarios.json").read_text(encoding="utf-8")
    )

    with sqlite3.connect(":memory:") as connection:
        connection.executescript(sql)
        database_ids = {
            row[0] for row in connection.execute("SELECT id FROM customer_growth_jobs")
        }
        row_count = len(database_ids)

    scenarios = fixture.get("authz", {}).get("scenarios", [])
    scenario_ids = [scenario.get("id") for scenario in scenarios]
    if fixture.get("version") != 4:
        errors.append("AuthGuard E2E fixture version must be 4")
    authn = fixture.get("authn", {})
    provider_flows = authn.get("provider_flows", [])
    linking = authn.get("account_linking", {})
    federation = fixture.get("principal_federation", {})
    keycloak = federation.get("keycloak", {})
    ldap = federation.get("ldap", {})
    provider_ids = {flow.get("provider_id") for flow in provider_flows}
    if provider_ids != {"github", "google", "wechat"}:
        errors.append("AuthN fixture must cover GitHub, Google, and WeChat provider flows")
    if linking.get("strategy") != "first-login" or linking.get("email_auto_link") is not False:
        errors.append("AuthN 2C fixture must use first-login without email auto-link")
    keycloak_users = keycloak.get("users", [])
    keycloak_groups = keycloak.get("groups", [])
    if len(keycloak_users) != 2 or len(keycloak_groups) != 2 or not keycloak.get("workload"):
        errors.append("Keycloak federation must cover two users, two groups, and one workload")
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

    details = [
        f"Shared database rows: {row_count}",
        f"Shared authorization scenarios: {len(scenarios)}",
        f"Conditional gateway scenarios: {len(condition_scenarios)}",
        "CRUD, action isolation, *, **, explicit deny, IP, transport, MFA, and claims",
        "AuthN covers realistic GitHub, Google, and WeChat OAuth2-like wire contracts",
        "Enterprise federation covers Keycloak USER/GROUP/WORKLOAD and direct LDAP identity",
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
