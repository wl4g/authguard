"""Phase 24: verify user/workload access through Envoy, AuthZ, and Biz."""

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
        environment.verify_gateway_authorization()
        passed = True
    except Exception:
        environment.details.append(traceback.format_exc())
    return VerificationResult(
        scenario_id="24",
        title="k3s phase 4/5: OIDC user/workload, Envoy, AuthZ, and Biz CRUD",
        passed=passed,
        duration_seconds=time.monotonic() - started,
        details=environment.details,
        commands=environment.commands,
    )
