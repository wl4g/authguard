"""Markdown evidence and report archival for repeatable E2E rounds."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import re
import shutil

from .config import REPORTS_DIR
from .model import VerificationResult


ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def archive_reports() -> Path | None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    current = [
        path
        for path in REPORTS_DIR.iterdir()
        if path.name != ".gitignore" and not path.name.startswith("archived-")
    ]
    if not current:
        return None
    archive = REPORTS_DIR / datetime.now().strftime("archived-%Y%m%d-%H%M%S")
    archive.mkdir()
    for path in current:
        shutil.move(str(path), archive / path.name)
    return archive


def write_round_report(round_number: int, result: VerificationResult) -> Path:
    round_dir = REPORTS_DIR / f"round-{round_number:02d}"
    round_dir.mkdir(parents=True, exist_ok=True)
    report = round_dir / f"{result.scenario_id}_{_slug(result.title)}.md"
    status = "PASS" if result.passed else "FAIL"
    lines = [
        f"# [{status}] {result.scenario_id} {result.title}",
        "",
        f"- Round: {round_number}",
        f"- Duration: {result.duration_seconds:.2f}s",
    ]
    lines.extend(f"- {detail}" for detail in result.details)
    for command in result.commands:
        lines.extend(
            [
                "",
                f"## `{' '.join(command.command)}`",
                "",
                f"- Working directory: `{command.cwd}`",
                f"- Exit code: {command.return_code}",
                f"- Duration: {command.duration_seconds:.2f}s",
                "",
                "```text",
                ANSI_ESCAPE.sub("", command.output).rstrip(),
                "```",
            ]
        )
    report.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return report


def write_summary(rounds: list[list[VerificationResult]]) -> Path:
    report = REPORTS_DIR / "00_summary.md"
    lines = ["# Customer Growth Job Authorization E2E Summary", ""]
    for index, results in enumerate(rounds, start=1):
        passed = sum(result.passed for result in results)
        lines.extend(
            [
                f"## Round {index}",
                "",
                f"Result: {passed}/{len(results)} verifier groups passed.",
                "",
                "| ID | Verifier | Result | Duration |",
                "| --- | --- | --- | ---: |",
            ]
        )
        for result in results:
            status = "PASS" if result.passed else "FAIL"
            lines.append(
                f"| {result.scenario_id} | {result.title} | {status} | "
                f"{result.duration_seconds:.2f}s |"
            )
        lines.append("")
    report.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return report


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
