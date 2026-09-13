"""Run the Spring Boot JPA business-service E2E project."""

from common.model import RunContext, VerificationResult
from common.project import verify_project


def verify(context: RunContext) -> VerificationResult:
    return verify_project(context, "14", "springboot-jpa-service")
