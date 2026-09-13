"""Run the Python SQLAlchemy business-service E2E project."""

from common.model import RunContext, VerificationResult
from common.project import verify_project


def verify(context: RunContext) -> VerificationResult:
    return verify_project(context, "12", "python-sqlalchemy-service")
