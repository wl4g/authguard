"""Run the Python SQLAlchemy business-service E2E project."""

from common.model import RunContext, VerificationResult
from common.project import verify_project
from verifier.other.base import BaseVerifier


class PythonSqlalchemyVerifier(BaseVerifier):
    scenario_id = "23"
    title = "Python + SQLAlchemy + SQLite"

    def run(self) -> VerificationResult:
        return verify_project(self.context, self.scenario_id, "python-sqlalchemy-service")


def verify(context: RunContext) -> VerificationResult:
    return PythonSqlalchemyVerifier(context).run()
