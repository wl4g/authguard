"""Run the Spring Boot JPA business-service E2E project."""

from common.model import RunContext, VerificationResult
from common.project import verify_project
from verifier.base_verifier import BaseVerifier


class SpringBootJpaVerifier(BaseVerifier):
    scenario_id = "14"
    title = "Spring Boot + JPA + H2"

    def run(self) -> VerificationResult:
        return verify_project(self.context, self.scenario_id, "springboot-jpa-service")


def verify(context: RunContext) -> VerificationResult:
    return SpringBootJpaVerifier(context).run()
