"""Phase 25: verify DB, logs, metrics, Jaeger, cache, and runtime health."""

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
        environment.verify_runtime_evidence()
        passed = True
    except Exception:
        environment.details.append(traceback.format_exc())
    return VerificationResult(
        scenario_id="25",
        title="k3s phase 5/5: PostgreSQL, logs, metrics, Jaeger, and runtime health",
        passed=passed,
        duration_seconds=time.monotonic() - started,
        details=environment.details,
        commands=environment.commands,
    )
