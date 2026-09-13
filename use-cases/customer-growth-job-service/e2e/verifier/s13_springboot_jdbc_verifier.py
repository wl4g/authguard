"""Run the Spring Boot JDBC business-service E2E project."""

from common.model import RunContext, VerificationResult
from common.project import verify_project
from verifier.base_verifier import BaseVerifier


class SpringBootJdbcVerifier(BaseVerifier):
    scenario_id = "13"
    title = "Spring Boot + JDBC + SQLite"

    def run(self) -> VerificationResult:
        return verify_project(self.context, self.scenario_id, "springboot-jdbc-service")


def verify(context: RunContext) -> VerificationResult:
    return SpringBootJdbcVerifier(context).run()
