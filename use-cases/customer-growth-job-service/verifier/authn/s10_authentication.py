"""Ordered s10 authentication convergence scenario."""
from __future__ import annotations
from verifier.authn.authn_protocol import AuthnProtocolVerifier
from verifier.context import VerificationContext, VerificationResult, BaseVerifier
from verifier.authn.s11_oauth2 import E2ES11Oauth2Verifier
from verifier.authn.s12_oidc import E2ES12OidcVerifier
from verifier.authn.s13_password_totp import E2ES13PasswordTotpVerifier
from verifier.authn.s15_wallet import E2ES15WalletVerifier
from verifier.authn.s14_webauthn import E2ES14WebauthnVerifier


class E2ES10AuthenticationVerifier(BaseVerifier):
    """Converge every protocol only after AuthenticationResult."""

    def deploy(self, context: VerificationContext) -> None:
        """Reuse infrastructure owned by scenario 00."""

    def init(self, context: VerificationContext) -> None:
        """No additional scenario test data initialization is required."""

    scenario_id = "10"
    title = "Unified OAuth/OIDC, credential, WebAuthn, and CAIP/SIWX authentication"

    def verifier(self, context: VerificationContext) -> VerificationResult:
        return self.execute(self._verify)

    def _verify(self) -> None:
        self.step(
            "AuthN API and management listener isolation", self._listener_isolation
        )
        oauth = self._protocol(E2ES11Oauth2Verifier)
        self._protocol(E2ES12OidcVerifier)
        self.context.state["github_login"] = oauth["github"]
        standalone = self._protocol(E2ES13PasswordTotpVerifier)
        self.context.state["standalone"] = standalone
        self._protocol(E2ES14WebauthnVerifier)
        self._protocol(E2ES15WalletVerifier)
        self.step(
            "Unified AuthN: one credential table and protocol-independent Principal boundary",
            self._storage_boundary,
        )

    def _protocol(self, verifier_type):
        verifier = verifier_type(self)
        verifier.deploy(self.context)
        verifier.init(self.context)
        return verifier.verifier(self.context)

    def _listener_isolation(self) -> None:
        with self._forward_service(self.authguard_authn_service, 8082) as api_port:
            status, _ = self._http(api_port, "customer-growth.local", "/healthz")
            self._expect_status(
                "management endpoint on AuthN API listener", status, 404
            )
        with self._forward_service(
            self.authguard_authn_service, self.management_port
        ) as mgmt_port:
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
            "SELECT table_name FROM information_schema.tables WHERE table_schema='authguard' AND (table_name LIKE 'iam_%credential%' OR table_name LIKE 'iam_%wallet%' OR table_name LIKE 'iam_%challenge%' OR table_name LIKE 'iam_%passkey%') ORDER BY table_name;",
        ).splitlines()
        if tables != ["iam_standalone_credential"]:
            raise RuntimeError(
                f"AuthN storage did not converge to one credential table: {tables}"
            )
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
            "Password/TOTP/WebAuthn, OAuth/OIDC, and CAIP wallets all emitted the same canonical JWT and persisted only protocol-neutral identity bindings"
        )
        self.details.append(
            f"Persisted authenticated accounts: {AuthnProtocolVerifier.verify_persisted_account_state(self.infrastructure.postgresql_query)}"
        )
