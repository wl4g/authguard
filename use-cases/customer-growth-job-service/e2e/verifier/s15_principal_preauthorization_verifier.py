"""Phase 15: federate Principals and apply administrator pre-authorization."""

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
        environment.verify_principal_preauthorization()
        passed = True
    except Exception:
        environment.details.append(traceback.format_exc())
    return VerificationResult(
        scenario_id="15",
        title="Core 1/3: Keycloak/LDAP federation and administrator pre-authorization",
        passed=passed,
        duration_seconds=time.monotonic() - started,
        details=environment.details,
        commands=environment.commands,
    )
