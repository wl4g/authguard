"""Ordered s10 authentication convergence scenario."""

from __future__ import annotations

from common.model import RunContext, VerificationResult
from verifier.authn.oauth2.s11_oauth2 import OAuth2AuthenticationVerifier
from verifier.authn.oidc.s12_oidc import OidcAuthenticationVerifier
from verifier.authn.password.s13_password_totp import PasswordTotpAuthenticationVerifier
from verifier.authn.wallet.s15_wallet import WalletAuthenticationVerifier
from verifier.authn.webauthn.s14_webauthn import WebAuthnAuthenticationVerifier
from verifier.other.base import BaseVerifier


class UnifiedAuthenticationVerifier(BaseVerifier):
    """Converge every protocol only after AuthenticationResult."""

    scenario_id = "10"
    title = "Unified OAuth/OIDC, credential, WebAuthn, and CAIP/SIWX authentication"

    def run(self) -> VerificationResult:
        return self.execute(self._verify)

    def _verify(self) -> None:
        self.step("AuthN API and management listener isolation", self._listener_isolation)
        oauth = OAuth2AuthenticationVerifier(self).verify()
        OidcAuthenticationVerifier(self).verify()
        standalone = PasswordTotpAuthenticationVerifier(self).verify(oauth["github"])
        WebAuthnAuthenticationVerifier(self).verify(standalone)
        WalletAuthenticationVerifier(self).verify(standalone)
        self.step(
            "Unified AuthN: one credential table and protocol-independent Principal boundary",
            self._storage_boundary,
        )

    def _listener_isolation(self) -> None:
        with self._forward_service(self.authguard_authn_service, 8082) as api_port:
            status, _ = self._http(api_port, "customer-growth.local", "/healthz")
            self._expect_status("management endpoint on AuthN API listener", status, 404)
        with self._forward_service(self.authguard_authn_service, 9091) as mgmt_port:
            status, _ = self._http(
                mgmt_port, "authguard-mgmt.local", "/.well-known/authn.json"
            )
            self._expect_status("AuthN API on management listener", status, 404)
            status, _ = self._http(mgmt_port, "authguard-mgmt.local", "/healthz")
            self._expect_status("AuthN management health endpoint", status, 200)
        self.details.append(
            "AuthN :8082 exposes only authentication APIs; :9091 exposes only health, metrics, and profiling"
        )

    def _storage_boundary(self) -> None:
        tables = self._postgresql_query(
            self._postgresql_pod(),
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema='authguard' AND "
            "(table_name LIKE 'iam_%credential%' OR table_name LIKE 'iam_%wallet%' "
            "OR table_name LIKE 'iam_%challenge%' OR table_name LIKE 'iam_%passkey%') "
            "ORDER BY table_name;",
        ).splitlines()
        if tables != ["iam_standalone_credential"]:
            raise RuntimeError(f"AuthN storage did not converge to one credential table: {tables}")
        providers = set(
            self._postgresql_query(
                self._postgresql_pod(),
                "SELECT DISTINCT provider FROM iam_principal_identity ORDER BY provider;",
            ).splitlines()
        )
        required = {"github", "google", "wechat", "qq", "standalone", "wallet"}
        if not required.issubset(providers):
            raise RuntimeError(
                f"unified identity bindings are missing providers: {sorted(required - providers)}"
            )
        self.details.append(
            "Password/TOTP/WebAuthn, OAuth/OIDC, and CAIP wallets all emitted the "
            "same canonical JWT and persisted only protocol-neutral identity bindings"
        )


def verify(context: RunContext) -> VerificationResult:
    return UnifiedAuthenticationVerifier(context).run()
