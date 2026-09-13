"""Clean-build-test lifecycle shared by all language project verifiers."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
import shutil
import time

from .config import CONFIG_DIR, PROJECTS, PROJECT_ROOT
from .model import RunContext, VerificationResult
from .process import run_command


CASE_MARKER = re.compile(r"AUTHGUARD_E2E_CASE id=([A-Za-z0-9_.-]+)")
PROJECT_VERIFIERS = dict(zip(("10", "11", "12", "13", "14"), PROJECTS, strict=True))


def verify_project(
    context: RunContext, scenario_id: str, project_name: str
) -> VerificationResult:
    project = PROJECTS[project_name]
    started = time.monotonic()
    commands = []
    details = [f"Project: {project.path.relative_to(PROJECT_ROOT)}"]

    if context.clean:
        _remove_generated_python_artifacts(project.path)
        for command in project.clean_commands:
            result = run_command(
                command,
                cwd=project.path,
                environment=project.environment,
                timeout_seconds=context.timeout_seconds,
            )
            commands.append(result)
            if not result.passed:
                return _result(
                    scenario_id, project.title, started, details, commands, False
                )

    for command in project.setup_commands:
        result = run_command(
            command,
            cwd=PROJECT_ROOT,
            environment=project.environment,
            timeout_seconds=context.timeout_seconds,
        )
        commands.append(result)
        if not result.passed:
            return _result(
                scenario_id, project.title, started, details, commands, False
            )

    test_result = run_command(
        project.test_command,
        cwd=project.path,
        environment=project.environment,
        timeout_seconds=context.timeout_seconds,
    )
    commands.append(test_result)
    expected_cases = _authorization_scenario_ids()
    executed_cases = tuple(CASE_MARKER.findall(test_result.output))
    counts = Counter(executed_cases)
    missing = sorted(set(expected_cases) - counts.keys())
    unexpected = sorted(counts.keys() - set(expected_cases))
    duplicated = sorted(case_id for case_id, count in counts.items() if count != 1)
    coverage_ok = executed_cases == expected_cases
    details.append(
        f"Authorization scenario executions: {len(executed_cases)}/{len(expected_cases)}"
    )
    if not coverage_ok:
        details.append(
            f"Scenario coverage mismatch: missing={missing}, unexpected={unexpected}, "
            f"duplicated={duplicated}"
        )
    return _result(
        scenario_id,
        project.title,
        started,
        details,
        commands,
        test_result.passed and coverage_ok,
        executed_cases,
    )


def verify_scenario_matrix(results: list[VerificationResult]) -> VerificationResult | None:
    by_id = {result.scenario_id: result for result in results}
    if not PROJECT_VERIFIERS.keys() <= by_id.keys():
        return None

    expected_cases = _authorization_scenario_ids()
    expected_total = len(expected_cases) * len(PROJECT_VERIFIERS)
    actual_total = sum(len(by_id[scenario_id].case_executions) for scenario_id in PROJECT_VERIFIERS)
    complete = all(
        by_id[scenario_id].case_executions == expected_cases
        for scenario_id in PROJECT_VERIFIERS
    )
    details = [
        f"Cross-service authorization matrix: {actual_total}/{expected_total} executions",
        f"Formula: {len(expected_cases)} fixture cases × {len(PROJECT_VERIFIERS)} Biz services",
    ]
    details.extend(
        f"{project_name}: {len(by_id[scenario_id].case_executions)}/{len(expected_cases)}"
        for scenario_id, project_name in PROJECT_VERIFIERS.items()
    )
    return VerificationResult(
        scenario_id="18",
        title="Cross-service authorization scenario matrix",
        passed=complete and actual_total == expected_total,
        duration_seconds=0,
        details=details,
    )


def _authorization_scenario_ids() -> tuple[str, ...]:
    fixture = json.loads(
        (CONFIG_DIR / "authguard-e2e-scenarios.json").read_text(encoding="utf-8")
    )
    return tuple(scenario["id"] for scenario in fixture["authz"]["scenarios"])


def _remove_generated_python_artifacts(project_dir: Path) -> None:
    for name in ("__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"):
        for path in project_dir.rglob(name):
            if path.is_dir():
                shutil.rmtree(path)


def _result(
    scenario_id: str,
    title: str,
    started: float,
    details: list[str],
    commands: list,
    passed: bool,
    case_executions: tuple[str, ...] = (),
) -> VerificationResult:
    return VerificationResult(
        scenario_id=scenario_id,
        title=title,
        passed=passed,
        duration_seconds=time.monotonic() - started,
        details=details,
        commands=commands,
        case_executions=case_executions,
    )
