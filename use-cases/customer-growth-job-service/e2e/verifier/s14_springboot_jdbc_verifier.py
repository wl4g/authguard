"""Run the Spring Boot JDBC business-service E2E project."""

from common.model import RunContext, VerificationResult
from common.project import verify_project


def verify(context: RunContext) -> VerificationResult:
    return verify_project(context, "14", "springboot-jdbc-service")
