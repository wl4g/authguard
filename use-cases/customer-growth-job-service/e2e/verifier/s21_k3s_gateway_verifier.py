"""Verify five workloads and their authentication/authorization trace on k3s."""

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
        environment.verify_scenarios()
        passed = True
    except Exception:
        environment.details.append(traceback.format_exc())
    return VerificationResult(
        scenario_id="21",
        title="k3s: Keycloak JWT -> Envoy ext_authz -> Authguard with Jaeger evidence",
        passed=passed,
        duration_seconds=time.monotonic() - started,
        details=environment.details,
        commands=environment.commands,
    )
