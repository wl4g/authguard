#!/usr/bin/env python3
"""Isolate only Envoy Gateway's cluster-scoped RBAC for an E2E deployment."""

from __future__ import annotations

import os
import sys


class EnvoyGatewayClusterScopeIsolator:
    """Namespace only the vendor ClusterRole and ClusterRoleBinding names.

    The Envoy Gateway control plane and generated data plane keep their normal
    component names inside the disposable E2E namespace.  Only these two RBAC
    objects are cluster-scoped, therefore they need an E2E namespace-derived
    suffix to allow a concurrent suite to install another controller safely.
    """

    role_name = "envoy-gateway-helm-envoy-gateway-role"
    binding_name = "envoy-gateway-helm-envoy-gateway-rolebinding"

    def __init__(self) -> None:
        self.cluster_scope_prefix = os.getenv(
            "AUTHGUARD_E2E_CLUSTER_RESOURCE_PREFIX", "e2e-authguard-system"
        )
        self.isolated_role_name = f"{self.cluster_scope_prefix}-envoy-gateway-role"
        self.isolated_binding_name = (
            f"{self.cluster_scope_prefix}-envoy-gateway-rolebinding"
        )

    def run(self) -> None:
        documents = sys.stdin.read().split("\n---\n")
        sys.stdout.write("\n---\n".join(self._isolate(document) for document in documents))

    def _isolate(self, document: str) -> str:
        """Rewrite references only within the two expected cluster-scoped kinds."""
        scoped_document = f"\n{document}"
        if "\nkind: ClusterRole\n" in scoped_document:
            return document.replace(self.role_name, self.isolated_role_name)
        if "\nkind: ClusterRoleBinding\n" in scoped_document:
            return document.replace(self.binding_name, self.isolated_binding_name).replace(
                self.role_name, self.isolated_role_name
            )
        return document


if __name__ == "__main__":
    EnvoyGatewayClusterScopeIsolator().run()
