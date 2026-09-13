"""Run the Go sqlx business-service E2E project."""

from common.model import RunContext, VerificationResult
from common.project import verify_project
from verifier.base_verifier import BaseVerifier


class GolangSqlxVerifier(BaseVerifier):
    scenario_id = "10"
    title = "Go + sqlx + SQLite"

    def run(self) -> VerificationResult:
        return verify_project(self.context, self.scenario_id, "golang-sqlx-service")


def verify(context: RunContext) -> VerificationResult:
    return GolangSqlxVerifier(context).run()
