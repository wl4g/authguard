"""Clean-build-test lifecycle shared by all language project verifiers."""
from __future__ import annotations
from util.constant import E2EOtherDefinitions
from collections import Counter
import json
import re
import shutil
import time
from pathlib import Path
from verifier.context import VerificationContext, VerificationResult
from util.process import E2EProcessHelper

CASE_MARKER = re.compile("AUTHGUARD_E2E_CASE id=([A-Za-z0-9_.-]+)")
PROJECT_VERIFIERS = dict(
    zip(("21", "22", "23", "24", "25"), E2EOtherDefinitions.PROJECTS, strict=True)
)


class ProjectVerifier:
    @staticmethod
    def verify_project(
        context: VerificationContext, scenario_id: str, project_name: str
    ) -> VerificationResult:
        project = E2EOtherDefinitions.PROJECTS[project_name]
        started = time.monotonic()
        commands = []
        details = [
            f"Project: {project.path.relative_to(E2EOtherDefinitions.PROJECT_ROOT)}"
        ]
        if context.clean:
            ProjectVerifier._remove_generated_python_artifacts(project.path)
            for command in project.clean_commands:
                result = E2EProcessHelper.run_command(
                    command,
                    cwd=project.path,
                    environment=project.environment,
                    timeout_seconds=context.timeout_seconds,
                )
                commands.append(result)
                if not result.passed:
                    return ProjectVerifier._result(
                        scenario_id, project.title, started, details, commands, False
                    )
        for command in project.setup_commands:
            result = E2EProcessHelper.run_command(
                command,
                cwd=E2EOtherDefinitions.PROJECT_ROOT,
                environment=project.environment,
                timeout_seconds=context.timeout_seconds,
            )
            commands.append(result)
            if not result.passed:
                return ProjectVerifier._result(
                    scenario_id, project.title, started, details, commands, False
                )
        test_result = E2EProcessHelper.run_command(
            project.test_command,
            cwd=project.path,
            environment=project.environment,
            timeout_seconds=context.timeout_seconds,
        )
        commands.append(test_result)
        expected_cases = ProjectVerifier._authorization_scenario_ids()
        executed_cases = tuple(CASE_MARKER.findall(test_result.output))
        counts = Counter(executed_cases)
        missing = sorted(set(expected_cases) - counts.keys())
        unexpected = sorted(counts.keys() - set(expected_cases))
        duplicated = sorted(
            (case_id for case_id, count in counts.items() if count != 1)
        )
        coverage_ok = executed_cases == expected_cases
        details.append(
            f"Authorization scenario executions: {len(executed_cases)}/{len(expected_cases)}"
        )
        if not coverage_ok:
            details.append(
                f"Scenario coverage mismatch: missing={missing}, unexpected={unexpected}, duplicated={duplicated}"
            )
        return ProjectVerifier._result(
            scenario_id,
            project.title,
            started,
            details,
            commands,
            test_result.passed and coverage_ok,
            executed_cases,
        )

    @staticmethod
    def verify_scenario_matrix(
        results: list[VerificationResult],
    ) -> VerificationResult | None:
        by_id = {result.scenario_id: result for result in results}
        if not PROJECT_VERIFIERS.keys() <= by_id.keys():
            return None
        expected_cases = ProjectVerifier._authorization_scenario_ids()
        expected_total = len(expected_cases) * len(PROJECT_VERIFIERS)
        actual_total = sum(
            (
                len(by_id[scenario_id].case_executions)
                for scenario_id in PROJECT_VERIFIERS
            )
        )
        complete = all(
            (
                by_id[scenario_id].case_executions == expected_cases
                for scenario_id in PROJECT_VERIFIERS
            )
        )
        details = [
            f"Cross-service authorization matrix: {actual_total}/{expected_total} executions",
            f"Formula: {len(expected_cases)} scenario data cases × {len(PROJECT_VERIFIERS)} Biz services",
        ]
        details.extend(
            (
                f"{project_name}: {len(by_id[scenario_id].case_executions)}/{len(expected_cases)}"
                for scenario_id, project_name in PROJECT_VERIFIERS.items()
            )
        )
        return VerificationResult(
            scenario_id="29",
            title="Cross-service authorization scenario matrix",
            passed=complete and actual_total == expected_total,
            duration_seconds=0,
            details=details,
        )

    @staticmethod
    def _authorization_scenario_ids() -> tuple[str, ...]:
        scenario_data = json.loads(
            E2EOtherDefinitions.AUTHGUARD_SCENARIOS_PATH.read_text(encoding="utf-8")
        )
        return tuple(
            (scenario["id"] for scenario in scenario_data["authz"]["scenarios"])
        )

    @staticmethod
    def _remove_generated_python_artifacts(project_dir: Path) -> None:
        for name in ("__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"):
            for path in project_dir.rglob(name):
                if path.is_dir():
                    shutil.rmtree(path)

    @staticmethod
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
