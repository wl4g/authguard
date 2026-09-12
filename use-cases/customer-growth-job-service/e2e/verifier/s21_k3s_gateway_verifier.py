"""Phase 21: deploy the complete real E2E topology with Helm."""

from __future__ import annotations

import time
import traceback

from common.kubernetes import KubernetesE2E
from common.model import RunContext, VerificationResult


def verify(context: RunContext) -> VerificationResult:
    started = time.monotonic()
    environment = KubernetesE2E(context)
    passed = False
    try:
        environment.verify_prerequisites()
        environment.redeploy()
        passed = True
    except Exception:
        environment.details.append(traceback.format_exc())
    return VerificationResult(
        scenario_id="21",
        title="k3s phase 1/5: Helm deployment and middleware initialization",
        passed=passed,
        duration_seconds=time.monotonic() - started,
        details=environment.details,
        commands=environment.commands,
    )
