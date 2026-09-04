"""Verify that the use case has one cohesive root and five independent projects."""

from __future__ import annotations

import time

from common.config import CONFIG_DIR, DEPLOY_DIR, PROJECTS, USE_CASE_DIR
from common.model import RunContext, VerificationResult


REQUIRED_PATHS = {
    "golang-sqlx-service": (
        "pkg/authorization",
        "pkg/controller",
        "pkg/dto",
        "pkg/entity",
        "pkg/repository",
        "pkg/service",
        "tests/customer_growth_job_e2e_test.go",
    ),
    "rust-sqlx-service": (
        "src/customer_growth_job_authorization.rs",
        "src/customer_growth_job_controller.rs",
        "src/customer_growth_job_dto.rs",
        "src/customer_growth_job_entity.rs",
        "src/customer_growth_job_repository.rs",
        "src/customer_growth_job_service.rs",
        "tests/customer_growth_job_e2e.rs",
    ),
    "python-sqlalchemy-service": (
        "app/authorization",
        "app/controller",
        "app/dto",
        "app/entity",
        "app/repository",
        "app/service",
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


def verify(_context: RunContext) -> VerificationResult:
    started = time.monotonic()
    errors: list[str] = []
    actual_projects = {
        path.name for path in DEPLOY_DIR.iterdir() if path.is_dir()
    }
    expected_projects = set(PROJECTS)
    if actual_projects != expected_projects:
        errors.append(
            f"deploy projects differ: actual={sorted(actual_projects)}, "
            f"expected={sorted(expected_projects)}"
        )

    use_case_siblings = {
        path.name for path in USE_CASE_DIR.parent.iterdir() if path.is_dir()
    }
    if use_case_siblings != {USE_CASE_DIR.name}:
        errors.append(f"unexpected use-cases roots: {sorted(use_case_siblings)}")

    for file_name in ("init.sql", "authorization-scenarios.json"):
        if not (CONFIG_DIR / file_name).is_file():
            errors.append(f"missing shared config/{file_name}")

    for project_name, required_paths in REQUIRED_PATHS.items():
        project_dir = DEPLOY_DIR / project_name
        for relative in required_paths:
            if not (project_dir / relative).exists():
                errors.append(f"{project_name}: missing {relative}")

    details = [
        "One use-case root",
        f"Five deploy projects: {', '.join(sorted(expected_projects))}",
        "Each project keeps authorization, controller, DTO, entity, repository, service, and E2E test boundaries",
    ]
    details.extend(errors)
    return VerificationResult(
        scenario_id="01",
        title="Use-case structure and project boundaries",
        passed=not errors,
        duration_seconds=time.monotonic() - started,
        details=details,
    )
