#!/usr/bin/env python3
"""Normalize Envoy Gateway's fixed upstream resource names for E2E review."""

from __future__ import annotations

import os
import sys


class EnvoyGatewayManifestPrefixer:
    """Apply the E2E resource prefix before Helm submits the vendor manifests."""

    upstream_name = "envoy-gateway"
    certgen_secret_name = "envoy-gateway"

    def __init__(self) -> None:
        self.e2e_name = os.getenv(
            "AUTHGUARD_E2E_ENVOY_GATEWAY_NAME", "e2e-authguard-envoy-gateway"
        )

    def run(self) -> None:
        manifest = sys.stdin.read().replace(self.upstream_name, self.e2e_name)
        # The upstream `envoy-gateway certgen` binary owns this Secret at runtime
        # and has no configurable name. Keep the Deployment reference aligned with
        # that internal contract; it creates no user-facing Pod name.
        manifest = manifest.replace(
            f"secretName: {self.e2e_name}",
            f"secretName: {self.certgen_secret_name}",
        )
        sys.stdout.write(self._restore_control_plane_service_name(manifest))

    def _restore_control_plane_service_name(self, manifest: str) -> str:
        """Keep Envoy Gateway's fixed xDS Service discovery contract intact."""
        documents = manifest.split("\n---\n")
        service_marker = "\nkind: Service\n"
        renamed_name = f"  name: {self.e2e_name}\n"
        original_name = f"  name: {self.upstream_name}\n"
        for index, document in enumerate(documents):
            if service_marker in f"\n{document}" and renamed_name in document:
                documents[index] = document.replace(renamed_name, original_name, 1)
        return "\n---\n".join(documents)


if __name__ == "__main__":
    EnvoyGatewayManifestPrefixer().run()
