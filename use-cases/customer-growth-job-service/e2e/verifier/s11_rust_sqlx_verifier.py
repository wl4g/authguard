"""Run the Rust sqlx business-service E2E project."""

from common.model import RunContext, VerificationResult
from common.project import verify_project
from verifier.base_verifier import BaseVerifier


class RustSqlxVerifier(BaseVerifier):
    scenario_id = "11"
    title = "Rust + sqlx + SQLite"

    def run(self) -> VerificationResult:
        return verify_project(self.context, self.scenario_id, "rust-sqlx-service")


def verify(context: RunContext) -> VerificationResult:
    return RustSqlxVerifier(context).run()
