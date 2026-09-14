"""Verify the deployed Customer Growth UI and its AuthGuard discovery contract."""

from __future__ import annotations

import json
import re

from common.model import RunContext, VerificationResult
from verifier.base_verifier import BaseVerifier


UI_HOST = "e2e-authguard-authn.customer-growth.local"


class CustomerGrowthUiVerifier(BaseVerifier):
    scenario_id = "19"
    title = "Customer Growth UI: deployed assets and dynamic AuthN capabilities"

    def run(self) -> VerificationResult:
        return self.execute(self._run_scenario)

    def _run_scenario(self) -> None:
        envoy_service = self._envoy_proxy_service()
        with self._forward_service(envoy_service, 8082) as port:
            self.step("load the deployed UI through Envoy", lambda: self._verify_page(port))
            self.step(
                "discover OAuth, standalone, and wallet capabilities",
                lambda: self._verify_metadata(port),
            )
            self.step(
                "route wallet API requests to AuthN instead of the SPA",
                lambda: self._verify_authn_route_precedence(port),
            )

    def _verify_page(self, port: int) -> None:
        status, html = self._http(port, UI_HOST, "/")
        self._expect_status("customer growth UI", status, 200)
        if '<div id="root"></div>' not in html:
            raise RuntimeError("customer growth UI root element is missing")
        match = re.search(r'<script[^>]+src="([^"]+)"', html)
        if not match:
            raise RuntimeError("customer growth UI JavaScript asset is missing")
        asset_status, bundle = self._http(port, UI_HOST, match.group(1))
        self._expect_status("customer growth UI JavaScript", asset_status, 200)
        required_contracts = {
            "login-id",
            "login-password",
            "login-totp",
            "login-password-submit",
            "login-wallet",
            "customer-home",
            "/.well-known/authn.json",
        }
        missing = sorted(value for value in required_contracts if value not in bundle)
        if missing:
            raise RuntimeError(f"customer growth UI bundle lacks contracts: {missing}")
        self.details.append("deployed SPA contains password/TOTP, wallet, and authenticated-home controls")

    def _verify_metadata(self, port: int) -> None:
        status, body = self._http(port, UI_HOST, "/.well-known/authn.json")
        self._expect_status("AuthN public metadata", status, 200)
        metadata = json.loads(body)
        providers = {
            provider.get("id", "").lower()
            for provider in metadata.get("oauth2", {}).get("providers", [])
        }
        expected = {"github", "google", "wechat", "qq"}
        if not expected.issubset(providers):
            raise RuntimeError(f"AuthN metadata lacks UI providers: {sorted(expected - providers)}")
        standalone = metadata.get("standalone", {})
        wallet = metadata.get("wallet", {})
        if not standalone.get("password") or not wallet.get("enabled"):
            raise RuntimeError("AuthN metadata did not enable password and wallet login")
        if "eip155:1" not in wallet.get("chains", []):
            raise RuntimeError("AuthN metadata lacks the E2E CAIP chain")
        self.details.append("UI capability discovery exposes GitHub, Google, WeChat, QQ, password, and CAIP")

    def _verify_authn_route_precedence(self, port: int) -> None:
        status, body = self._http(
            port,
            UI_HOST,
            "/auth/wallet/challenge",
            method="POST",
            json_body={"accountId": "not-a-caip-account"},
        )
        self._expect_status("wallet challenge validation", status, 400)
        if "CAIP-10" not in body:
            raise RuntimeError("wallet request was not handled by AuthN")


def verify(context: RunContext) -> VerificationResult:
    return CustomerGrowthUiVerifier(context).run()
