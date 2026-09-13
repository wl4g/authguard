"""Verify that every SDK implements the same named authorization contract cases."""

from __future__ import annotations

import re
import time
from pathlib import Path

from common.config import ADAPTERS_DIR
from common.model import RunContext, VerificationResult
from verifier.base_verifier import BaseVerifier


EXPECTED_CASES = 46


def _snake_case(name: str) -> str:
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return name.replace("__", "_").lower()


def _matches(paths: tuple[Path, ...], pattern: str) -> set[str]:
    expression = re.compile(pattern, re.MULTILINE)
    return {
        _snake_case(match)
        for path in paths
        for match in expression.findall(path.read_text(encoding="utf-8"))
    }


def _scenario_sets() -> dict[str, set[str]]:
    return {
        "go": _matches(
            tuple((ADAPTERS_DIR / "golang").glob("**/*_test.go")),
            r"^func Test([A-Za-z0-9]+)\(",
        ),
        "java": _matches(
            tuple((ADAPTERS_DIR / "java" / "src" / "test").glob("**/*.java")),
            r"@Test\s+void\s+([A-Za-z0-9]+)\(",
        ),
        "python": _matches(
            tuple((ADAPTERS_DIR / "python" / "tests").glob("test_*.py")),
            r"^\s*def test_([a-z0-9_]+)\(",
        ),
        "rust": _matches(
            (
                ADAPTERS_DIR / "rust" / "src" / "filter.rs",
                ADAPTERS_DIR / "rust" / "tests" / "sql_scope.rs",
            ),
            r"#\[(?:tokio::)?test\]\s+(?:async\s+)?fn\s+([a-z0-9_]+)\(",
        ),
    }


def _verify(_context: RunContext) -> VerificationResult:
    started = time.monotonic()
    scenarios = _scenario_sets()
    canonical = scenarios["java"]
    errors: list[str] = []
    for language, cases in scenarios.items():
        if len(cases) != EXPECTED_CASES:
            errors.append(f"{language}: expected {EXPECTED_CASES} cases, found {len(cases)}")
        missing = sorted(canonical - cases)
        extra = sorted(cases - canonical)
        if missing or extra:
            errors.append(f"{language}: missing={missing}, extra={extra}")

    details = [
        f"Java/Go/Python/Rust adapter contract: {EXPECTED_CASES} scenarios per SDK",
        "22 signed access-filter/resolver plus 24 context-codec/URN/SQL scenarios",
        "Scenario names are normalized and compared as identical sets",
    ]
    details.extend(errors)
    return VerificationResult(
        scenario_id="03",
        title="Cross-language adapter contract parity",
        passed=not errors,
        duration_seconds=time.monotonic() - started,
        details=details,
    )


class AdapterContractVerifier(BaseVerifier):
    scenario_id = "03"
    title = "Cross-language adapter contract parity"

    def run(self) -> VerificationResult:
        return self.step("compare all Go/Rust/Python/Java adapter cases", lambda: _verify(self.context))


def verify(context: RunContext) -> VerificationResult:
    return AdapterContractVerifier(context).run()
