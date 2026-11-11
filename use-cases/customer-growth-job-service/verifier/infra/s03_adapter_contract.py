"""Verify that every SDK implements the same named authorization contract cases."""
from __future__ import annotations
from util.constant import E2EOtherDefinitions
import re
import time
from pathlib import Path
from verifier.context import VerificationContext, VerificationResult, BaseVerifier

EXPECTED_CASES = 46


class E2ES03AdapterContractVerifier(BaseVerifier):
    def deploy(self, context: VerificationContext) -> None:
        """Reuse infrastructure owned by scenario 00."""

    def init(self, context: VerificationContext) -> None:
        """No additional scenario test data initialization is required."""

    scenario_id = "03"
    title = "Cross-language adapter contract parity"
    requires_deployer = False

    def verifier(self, context: VerificationContext) -> VerificationResult:
        return self.step(
            "compare all Go/Rust/Python/Java adapter cases",
            lambda: E2ES03AdapterContractVerifier._verify(self.context),
        )

    @staticmethod
    def _snake_case(name: str) -> str:
        name = re.sub("([A-Z]+)([A-Z][a-z])", "\\1_\\2", name)
        name = re.sub("([a-z0-9])([A-Z])", "\\1_\\2", name)
        return name.replace("__", "_").lower()

    @staticmethod
    def _matches(paths: tuple[Path, ...], pattern: str) -> set[str]:
        expression = re.compile(pattern, re.MULTILINE)
        return {
            E2ES03AdapterContractVerifier._snake_case(match)
            for path in paths
            for match in expression.findall(path.read_text(encoding="utf-8"))
        }

    @staticmethod
    def _scenario_sets() -> dict[str, set[str]]:
        return {
            "go": E2ES03AdapterContractVerifier._matches(
                tuple(
                    (E2EOtherDefinitions.ADAPTERS_DIR / "golang").glob("**/*_test.go")
                ),
                "^func Test([A-Za-z0-9]+)\\(",
            ),
            "java": E2ES03AdapterContractVerifier._matches(
                tuple(
                    (E2EOtherDefinitions.ADAPTERS_DIR / "java" / "src" / "test").glob(
                        "**/*.java"
                    )
                ),
                "@Test\\s+void\\s+([A-Za-z0-9]+)\\(",
            ),
            "python": E2ES03AdapterContractVerifier._matches(
                tuple(
                    (E2EOtherDefinitions.ADAPTERS_DIR / "python" / "tests").glob(
                        "test_*.py"
                    )
                ),
                "^\\s*def test_([a-z0-9_]+)\\(",
            ),
            "rust": E2ES03AdapterContractVerifier._matches(
                (
                    E2EOtherDefinitions.ADAPTERS_DIR / "rust" / "src" / "filter.rs",
                    E2EOtherDefinitions.ADAPTERS_DIR
                    / "rust"
                    / "tests"
                    / "sql_scope.rs",
                ),
                "#\\[(?:tokio::)?test\\]\\s+(?:async\\s+)?fn\\s+([a-z0-9_]+)\\(",
            ),
        }

    @staticmethod
    def _verify(_context: VerificationContext) -> VerificationResult:
        started = time.monotonic()
        scenarios = E2ES03AdapterContractVerifier._scenario_sets()
        canonical = scenarios["java"]
        errors: list[str] = []
        for language, cases in scenarios.items():
            if len(cases) != EXPECTED_CASES:
                errors.append(
                    f"{language}: expected {EXPECTED_CASES} cases, found {len(cases)}"
                )
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
