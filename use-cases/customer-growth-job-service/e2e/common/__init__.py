"""Shared primitives for the portable customer growth authorization E2E suite."""

from .config import DEFAULT_SCENARIOS, PROJECTS, SCENARIOS
from .model import CommandResult, RunContext, VerificationResult
from .process import run_command
from .project import verify_project, verify_scenario_matrix
from .report import archive_reports, write_round_report, write_summary

__all__ = [
    "DEFAULT_SCENARIOS",
    "PROJECTS",
    "SCENARIOS",
    "CommandResult",
    "RunContext",
    "VerificationResult",
    "archive_reports",
    "run_command",
    "verify_project",
    "verify_scenario_matrix",
    "write_round_report",
    "write_summary",
]
