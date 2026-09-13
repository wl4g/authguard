"""Verify that the use case has one cohesive root and five independent projects."""

from __future__ import annotations

import time

from common.config import CONFIG_DIR, DEPLOY_DIR, PROJECT_ROOT, PROJECTS, USE_CASE_DIR
from common.model import RunContext, VerificationResult


REQUIRED_PATHS = {
    "golang-sqlx-service": (
        "pkg/authorization",
        "pkg/controller",
        "pkg/dto",
        "pkg/entity",
        "pkg/repository",
        "pkg/service",
        "pkg/telemetry/telemetry.go",
        "tests/customer_growth_job_e2e_test.go",
    ),
    "rust-sqlx-service": (
        "src/authorization",
        "src/config.rs",
        "src/controller",
        "src/dto",
        "src/entity",
        "src/repository",
        "src/server.rs",
        "src/service",
        "tests/customer_growth_job_e2e.rs",
    ),
    "python-sqlalchemy-service": (
        "app/authorization",
        "app/controller",
        "app/dto",
        "app/entity",
        "app/repository",
        "app/service",
        "app/telemetry.py",
        "tests/test_customer_growth_job_e2e.py",
    ),
    "springboot-jdbc-service": (
        "src/main/java/com/authguard/usecases/authorization",
        "src/main/java/com/authguard/usecases/config",
        "src/main/java/com/authguard/usecases/controller",
        "src/main/java/com/authguard/usecases/dto",
        "src/main/java/com/authguard/usecases/entity",
        "src/main/java/com/authguard/usecases/repository",
        "src/main/java/com/authguard/usecases/service",
        "src/test/java/com/authguard/usecases/controller/CustomerGrowthJobControllerE2ETest.java",
    ),
    "springboot-jpa-service": (
        "src/main/java/com/authguard/usecases/authorization",
        "src/main/java/com/authguard/usecases/config",
        "src/main/java/com/authguard/usecases/controller",
        "src/main/java/com/authguard/usecases/dto",
        "src/main/java/com/authguard/usecases/entity",
        "src/main/java/com/authguard/usecases/repository",
        "src/main/java/com/authguard/usecases/service",
        "src/test/java/com/authguard/usecases/controller/CustomerGrowthJobControllerE2ETest.java",
    ),
}

SUPPORT_PROJECTS = {"mocksvc-idp-service"}

AUTHGUARD_REQUIRED_PATHS = (
    "src/common/src/route/management.rs",
    "src/common/src/utils/http_matcher.rs",
    "src/common/src/apm/pprof.rs",
    "src/common/src/apm/telemetry.rs",
    "src/common/src/apm/metrics.rs",
    "src/common/src/storage/base_sqlite.rs",
    "src/common/src/storage/base_postgres.rs",
    "src/common/src/storage/authn/flow_sqlite.rs",
    "src/common/src/storage/authn/flow_postgres.rs",
    "src/common/src/storage/principal_sqlite.rs",
    "src/common/src/storage/principal_postgres.rs",
    "src/common/src/storage/authz/role_sqlite.rs",
    "src/common/src/storage/authz/role_postgres.rs",
    "src/common/src/config/constants.rs",
    "src/common/src/config/config.rs",
    "src/common/src/model/principal.rs",
    "src/common/src/model/identity.rs",
    "src/common/src/model/role.rs",
    "src/common/src/model/policy.rs",
    "src/common/src/principal/custom.rs",
    "src/cmd/src/main.rs",
    "src/authn/src/server.rs",
    "src/authn/src/route/authentication.rs",
    "src/authn/src/handler/authentication.rs",
    "src/authn/src/provider/mod.rs",
    "src/authn/src/provider/oauth_like.rs",
    "src/authn/src/provider/github.rs",
    "src/authn/src/provider/google.rs",
    "src/authn/src/provider/oidc.rs",
    "src/authn/src/provider/qq.rs",
    "src/authn/src/provider/wechat.rs",
    "src/authn/src/principal/jit.rs",
    "src/authz/src/server.rs",
    "src/authz/src/route/authorization.rs",
    "src/authz/src/route/policy.rs",
    "src/authz/src/route/principal.rs",
    "src/authz/src/route/scim.rs",
    "src/authz/src/handler/policy.rs",
    "src/authz/src/handler/policy/runtime.rs",
    "src/authz/src/handler/authorization.rs",
    "src/authz/src/handler/principal.rs",
    "src/authz/src/handler/scim.rs",
    "src/authz/src/principal/ldap/mod.rs",
    "src/authz/src/principal/ldap/ldap.rs",
    "src/authz/src/principal/ldap/model.rs",
    "src/authz/src/principal/ldap/tests.rs",
    "src/authz/src/principal/keycloak/mod.rs",
    "src/authz/src/principal/keycloak/keycloak.rs",
    "src/authz/src/principal/keycloak/model.rs",
    "src/authz/src/principal/keycloak/tests.rs",
    "src/authz/src/principal/scim/mod.rs",
    "src/authz/src/principal/scim/model.rs",
    "src/authz/src/principal/scim/scim.rs",
    "src/authz/src/principal/scim/tests.rs",
)

AUTHGUARD_FORBIDDEN_PATHS = (
    "src/common/src/access",
    "src/common/src/security",
    "src/common/src/model/authn",
    "src/common/src/model/authz",
    "src/common/src/storage/database",
    "src/common/src/storage/entity",
    "src/common/src/storage/repository",
    "src/common/src/storage/sqlite.rs",
    "src/common/src/storage/postgres.rs",
    "src/authn/src/account",
    "src/authn/src/apm",
    "src/authn/src/config",
    "src/authn/src/main.rs",
    "src/authz/src/apm",
    "src/authz/src/config",
    "src/authz/src/model",
    "src/authz/src/utils",
    "src/authz/src/main.rs",
    "src/authz/src/handler/envoy_authz.rs",
    "src/authz/src/handler/management.rs",
    "src/authz/src/route/scim",
    "src/authz/src/principal/custom.rs",
    "src/authz/src/principal/resign.rs",
    "use-cases/customer-growth-job-service/e2e/deploy/mocksvc-service",
    "use-cases/customer-growth-job-service/e2e/deploy/scim-sync-agent-service",
)

REAL_E2E_VERIFIERS = (
    "s00_k3s_infrastructure_verifier.py",
    "s15_principal_preauthorization_verifier.py",
    "s16_authentication_verifier.py",
    "s17_gateway_authorization_verifier.py",
    "s20_observability_contract.py",
    "s21_runtime_evidence_verifier.py",
)

E2E_RESOURCE_PREFIX = "e2e-authguard-"
E2E_SQL_PREFIX = "e2e_authguard_"


def verify(_context: RunContext) -> VerificationResult:
    started = time.monotonic()
    errors: list[str] = []
    actual_projects = {
        path.name for path in DEPLOY_DIR.iterdir() if path.is_dir()
    }
    expected_projects = set(PROJECTS) | SUPPORT_PROJECTS
    if actual_projects != expected_projects:
        errors.append(
            f"deploy projects differ: actual={sorted(actual_projects)}, "
            f"expected={sorted(expected_projects)}"
        )

    for file_name in ("init.sql", "authguard-e2e-scenarios.json"):
        if not (CONFIG_DIR / file_name).is_file():
            errors.append(f"missing shared config/{file_name}")
    verifier_dir = USE_CASE_DIR / "e2e" / "verifier"
    for verifier in REAL_E2E_VERIFIERS:
        if not (verifier_dir / verifier).is_file():
            errors.append(f"missing ordered real-E2E verifier/{verifier}")

    observability_source = (
        verifier_dir / "s20_observability_contract.py"
    ).read_text(encoding="utf-8")
    jaeger_query_markers = (
        "class JaegerQueryClient",
        'self._get("/api/services")',
        'self._get(f"/api/traces?{query}")',
        'self._get(f"/api/traces/{trace.trace_id}")',
        "request.urlopen",
    )
    if missing := [
        marker for marker in jaeger_query_markers if marker not in observability_source
    ]:
        errors.append(f"phase 20 must query the real Jaeger API directly: {missing}")
    kubernetes_source = (
        USE_CASE_DIR / "e2e/common/kubernetes.py"
    ).read_text(encoding="utf-8")
    if any(
        endpoint in kubernetes_source
        for endpoint in ("/api/services", "/api/traces?", "/api/traces/")
    ):
        errors.append("Jaeger API verification must not leak into Kubernetes orchestration")

    deployment_sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            USE_CASE_DIR / "e2e/helm/values.yaml",
            USE_CASE_DIR / "e2e/helm/templates/_helpers.tpl",
            USE_CASE_DIR / "e2e/common/kubernetes.py",
        )
    )
    required_prefixes = (
        "e2e-authguard-customer-growth",
        "e2e_authguard_customer_growth",
        "range(28800, 28900)",
    )
    if missing := [value for value in required_prefixes if value not in deployment_sources]:
        errors.append(f"E2E resource/host-port isolation is incomplete: {missing}")
    if any(value in deployment_sources for value in ("e2e-customer-growth", "e2e_customer_growth")):
        errors.append("legacy E2E resource prefixes remain in deployment configuration")
    if "hostPort:" in deployment_sources or "nodePort:" in deployment_sources:
        errors.append("E2E charts must not allocate fixed cluster host ports")

    telemetry_contracts = {
        "Helm workloads": (
            USE_CASE_DIR / "e2e/helm/templates/workloads.yaml",
            ("OTEL_SERVICE_NAME", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
        ),
        "Go workload": (
            DEPLOY_DIR / "golang-sqlx-service/pkg/telemetry/telemetry.go",
            ("otlptracehttp.New", "otelhttp.NewHandler"),
        ),
        "Rust workload": (
            DEPLOY_DIR / "rust-sqlx-service/src/controller/http.rs",
            ("propagate_http_trace_context",),
        ),
        "Python workload": (
            DEPLOY_DIR / "python-sqlalchemy-service/app/telemetry.py",
            ("OTLPSpanExporter", "FlaskInstrumentor"),
        ),
    }
    for component, (path, markers) in telemetry_contracts.items():
        source = path.read_text(encoding="utf-8")
        if missing := [marker for marker in markers if marker not in source]:
            errors.append(f"{component} OTel wiring is incomplete: {missing}")
    for project in ("springboot-jdbc-service", "springboot-jpa-service"):
        pom = (DEPLOY_DIR / project / "pom.xml").read_text(encoding="utf-8")
        if "micrometer-tracing-bridge-otel" not in pom or "opentelemetry-exporter-otlp" not in pom:
            errors.append(f"{project}: Spring OTel exporter dependencies are incomplete")

    for protocol in ("keycloak", "ldap"):
        actual = {
            path.name
            for path in (PROJECT_ROOT / "src" / "authz" / "src" / "principal" / protocol).iterdir()
            if path.is_file()
        }
        expected = {f"{protocol}.rs", "model.rs", "tests.rs", "mod.rs"}
        if actual != expected:
            errors.append(
                f"{protocol} Principal package differs: actual={sorted(actual)}, "
                f"expected={sorted(expected)}"
            )

    for project_name, required_paths in REQUIRED_PATHS.items():
        project_dir = DEPLOY_DIR / project_name
        for relative in required_paths:
            if not (project_dir / relative).exists():
                errors.append(f"{project_name}: missing {relative}")

    for relative in AUTHGUARD_REQUIRED_PATHS:
        if not (PROJECT_ROOT / relative).is_file():
            errors.append(f"AuthGuard source boundary: missing {relative}")
    for relative in AUTHGUARD_FORBIDDEN_PATHS:
        if (PROJECT_ROOT / relative).exists():
            errors.append(f"AuthGuard source boundary: obsolete path remains: {relative}")

    details = [
        "One use-case root",
        f"Five business projects plus one realistic mock IdP: {', '.join(sorted(expected_projects))}",
        "Each project keeps authorization, controller, DTO, entity, repository, service, and E2E test boundaries",
        "AuthGuard common/AuthN/AuthZ source boundaries match the converged module contract",
        f"Deployed resources use {E2E_RESOURCE_PREFIX} / {E2E_SQL_PREFIX}; host forwards use 288xx",
        "Real k3s phases are ordered 00 deployment -> 15 pre-authorization -> "
        "16 AuthN -> 17 Envoy/AuthZ/Biz -> 21 runtime evidence; phase 20 is their "
        "shared fail-closed observability contract",
    ]
    details.extend(errors)
    return VerificationResult(
        scenario_id="01",
        title="Use-case structure and project boundaries",
        passed=not errors,
        duration_seconds=time.monotonic() - started,
        details=details,
    )
