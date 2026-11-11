"""Run the Spring Boot JPA business-service E2E project."""
from __future__ import annotations
from verifier.context import VerificationContext, VerificationResult, BaseVerifier
from verifier.sdk.sdk_scenario import ProjectVerifier


class E2ES25SpringbootJpaVerifier(BaseVerifier):
    def deploy(self, context: VerificationContext) -> None:
        """Reuse infrastructure owned by scenario 00."""

    def init(self, context: VerificationContext) -> None:
        """No additional scenario test data initialization is required."""

    requires_deployer = False
    scenario_id = "25"
    title = "Spring Boot + JPA + H2"

    def verifier(self, context: VerificationContext) -> VerificationResult:
        return ProjectVerifier.verify_project(
            self.context, self.scenario_id, "biz-springboot-jpa-service"
        )
