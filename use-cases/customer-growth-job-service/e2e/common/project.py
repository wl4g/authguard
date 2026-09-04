"""Clean-build-test lifecycle shared by all language project verifiers."""

from __future__ import annotations

from pathlib import Path
import shutil
import time

from .config import PROJECTS, PROJECT_ROOT
from .model import RunContext, VerificationResult
from .process import run_command


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
    details.append("Shared fixture: 53 CRUD, wildcard, deny, action, and condition scenarios")
    return _result(
        scenario_id,
        project.title,
        started,
        details,
        commands,
        test_result.passed,
    )


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
) -> VerificationResult:
    return VerificationResult(
        scenario_id=scenario_id,
        title=title,
        passed=passed,
        duration_seconds=time.monotonic() - started,
        details=details,
        commands=commands,
    )
