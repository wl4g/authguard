"""Markdown evidence and report archival for repeatable E2E rounds."""
from __future__ import annotations
from util.constant import E2EOtherDefinitions
from datetime import datetime
from pathlib import Path
import re
import shutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from verifier.context import VerificationResult


class E2EReportHelper:
    ANSI_ESCAPE = re.compile("\\x1b\\[[0-?]*[ -/]*[@-~]")

    @staticmethod
    def archive_reports() -> Path | None:
        E2EOtherDefinitions.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        current = [
            path
            for path in E2EOtherDefinitions.REPORTS_DIR.iterdir()
            if path.name not in {".gitignore", ".runtime"}
            and (not path.name.startswith("archived-"))
        ]
        if not current:
            return None
        archive = E2EOtherDefinitions.REPORTS_DIR / datetime.now().strftime(
            "archived-%Y%m%d-%H%M%S-%f"
        )
        archive.mkdir()
        for path in current:
            shutil.move(str(path), archive / path.name)
        return archive

    @staticmethod
    def write_round_report(round_number: int, result: VerificationResult) -> Path:
        round_dir = E2EOtherDefinitions.REPORTS_DIR / f"round-{round_number:02d}"
        round_dir.mkdir(parents=True, exist_ok=True)
        report = (
            round_dir / f"{result.scenario_id}_{E2EReportHelper._slug(result.title)}.md"
        )
        status = "PASS" if result.passed else "FAIL"
        lines = [
            f"# [{status}] {result.scenario_id} {result.title}",
            "",
            f"- Round: {round_number}",
            f"- Duration: {result.duration_seconds:.2f}s",
        ]
        lines.extend((f"- {detail}" for detail in result.details))
        if result.evidence:
            lines.extend(["", "## Evidence", ""])
            for artifact in result.evidence:
                relative = artifact.path.relative_to(round_dir)
                lines.append(
                    f"- [{artifact.case_id} — {artifact.title}]({relative.as_posix()}) (`{artifact.kind}`)"
                )
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
                    E2EReportHelper.ANSI_ESCAPE.sub("", command.output).rstrip(),
                    "```",
                ]
            )
        report.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        return report

    @staticmethod
    def write_summary(rounds: list[list[VerificationResult]]) -> Path:
        report = E2EOtherDefinitions.REPORTS_DIR / "00_summary.md"
        lines = ["# Customer Growth Job Authorization E2E Summary", ""]
        for index, results in enumerate(rounds, start=1):
            passed = sum((result.passed for result in results))
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
                    f"| {result.scenario_id} | {result.title} | {status} | {result.duration_seconds:.2f}s |"
                )
            lines.append("")
        report.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        return report

    @staticmethod
    def _slug(value: str) -> str:
        return re.sub("[^a-z0-9]+", "_", value.lower()).strip("_")
