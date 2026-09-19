"""AuthN s12 OIDC bearer-normalization verifier."""

from __future__ import annotations

import json
from urllib import parse, request

from common.kubernetes import AUTHN_HOST
from verifier.authn.other.protocol import AuthenticatedLogin, AuthnProtocolVerifier


class OidcAuthenticationVerifier(AuthnProtocolVerifier):
    """Use a real Keycloak token, then converge twice through the shared pipeline."""

    def verify(self) -> AuthenticatedLogin:
        envoy_service = self._envoy_proxy_service()
        with (
            self._forward_service(self.keycloak_service, 8080) as keycloak_port,
            self._forward_service(envoy_service, 8082) as authn_port,
        ):
            external = self.scenario.step(
                "OIDC: issue a real Keycloak user access token",
                lambda: self._password_token(
                    keycloak_port,
                    "authn-protocol-tester",
                    "authn-protocol-tester-password",
                ),
            )
            first = self.scenario.step(
                "OIDC: introspect and converge into the unified AuthGuard JWT",
                lambda: self._exchange(authn_port, external),
            )
            repeated = self.scenario.step(
                "OIDC: repeated proof reuses the canonical Principal",
                lambda: self._exchange(authn_port, external, first.principal_id),
            )
            self.scenario.step(
                "OIDC: reject GROUP authentication and unknown request fields",
                lambda: self._negative_contract(authn_port, external),
            )
        return repeated

    def _exchange(
        self,
        port: int,
        external_token: str,
        expected_principal_id: str | None = None,
    ) -> AuthenticatedLogin:
        status, payload = self.post(
            port,
            "/auth/oauth2/e2e-authguard-keycloak/token-exchange",
            {"subjectToken": external_token, "kind": "USER"},
        )
        return self.canonical_login(
            status,
            payload,
            expected_amr=["oidc"],
            expected_principal_id=expected_principal_id,
        )

    def _negative_contract(self, port: int, external_token: str) -> None:
        status, payload = self.post(
            port,
            "/auth/oauth2/e2e-authguard-keycloak/token-exchange",
            {"subjectToken": external_token, "kind": "GROUP"},
        )
        self.expect_error(status, payload, 400, "invalid_request")
        status, _ = self.post(
            port,
            "/auth/oauth2/e2e-authguard-keycloak/token-exchange",
            {"subjectToken": external_token, "kind": "USER", "signatureValid": True},
        )
        if status != 422:
            raise RuntimeError(f"OIDC unknown fields must be rejected with HTTP 422, got {status}")

    @staticmethod
    def _password_token(port: int, username: str, password: str) -> str:
        payload = parse.urlencode(
            {
                "grant_type": "password",
                "client_id": "customer-growth-job-service",
                "username": username,
                "password": password,
                "scope": "openid profile email",
            }
        ).encode()
        outgoing = request.Request(
            f"http://127.0.0.1:{port}/realms/example-corp/protocol/openid-connect/token",
            data=payload,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with request.urlopen(outgoing, timeout=15) as response:
            return json.loads(response.read())["access_token"]
