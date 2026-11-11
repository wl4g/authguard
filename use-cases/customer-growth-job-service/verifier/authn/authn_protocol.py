"""Shared assertions for protocol-specific AuthN verifier classes."""
from __future__ import annotations
from util.postgres import E2EPostgresChecker
from dataclasses import dataclass
import json
import time
from typing import Any
from verifier.context import BaseVerifier


@dataclass(frozen=True)
class AuthenticatedLogin:
    access_token: str
    principal_id: str
    claims: dict[str, Any]
    response: dict[str, Any]


class AuthnProtocolVerifier:
    """Composition base that keeps AuthN helpers out of generic infrastructure."""

    def __init__(self, scenario: BaseVerifier) -> None:
        self.scenario = scenario

    def __getattr__(self, name: str):
        return getattr(self.scenario, name)

    def post(
        self,
        port: int,
        path: str,
        payload: dict[str, Any],
        *,
        bearer: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        headers = {"Authorization": f"Bearer {bearer}"} if bearer else None
        status, body = self._http(
            port,
            "e2e-authguard-authn.customer-growth.local",
            path,
            method="POST",
            headers=headers,
            json_body=payload,
        )
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"_raw": body}
        if not isinstance(parsed, dict):
            raise RuntimeError(f"{path}: response JSON is not an object")
        return (status, parsed)

    def expect_error(
        self,
        status: int,
        payload: dict[str, Any],
        expected_status: int,
        expected_code: str,
    ) -> None:
        if status != expected_status or payload.get("code") != expected_code:
            raise RuntimeError(
                f"expected HTTP {expected_status}/{expected_code}, got HTTP {status}/{payload}"
            )
        self.scenario.details.append(
            f"HTTP {expected_status} with error code {expected_code}: PASS"
        )

    def canonical_login(
        self,
        status: int,
        payload: dict[str, Any],
        *,
        expected_amr: list[str],
        expected_acr: str | None = None,
        expected_principal_id: str | None = None,
    ) -> AuthenticatedLogin:
        if status != 200:
            raise RuntimeError(
                f"authentication expected HTTP 200, got {status}: {payload}"
            )
        token = payload.get("accessToken", "")
        principal = payload.get("principal") or {}
        principal_id = principal.get("principalId")
        claims = self._jwt_claims(token)
        now = int(time.time())
        required = {
            "iss": self.authn_issuer,
            "aud": "customer-growth-job-service",
            "sub": principal_id,
            "principal_id": principal_id,
            "principal_kind": "USER",
            "amr": expected_amr,
        }
        mismatch = {
            key: (value, claims.get(key))
            for key, value in required.items()
            if claims.get(key) != value
        }
        if mismatch or not isinstance(principal_id, str) or (not principal_id):
            raise RuntimeError(f"canonical AuthGuard JWT mismatch: {mismatch}")
        if expected_principal_id is not None and principal_id != expected_principal_id:
            raise RuntimeError(
                f"expected Principal {expected_principal_id!r}, got {principal_id!r}"
            )
        if expected_acr is None:
            if "acr" in claims:
                raise RuntimeError(f"unexpected JWT acr: {claims['acr']!r}")
        elif claims.get("acr") != expected_acr:
            raise RuntimeError(
                f"expected JWT acr {expected_acr!r}, got {claims.get('acr')!r}"
            )
        auth_time = claims.get("auth_time")
        issued_at = claims.get("iat")
        expires_at = claims.get("exp")
        if not all(
            (isinstance(value, int) for value in (auth_time, issued_at, expires_at))
        ):
            raise RuntimeError("canonical JWT lacks integer auth_time/iat/exp")
        if (
            abs(now - auth_time) > 30
            or abs(now - issued_at) > 30
            or expires_at <= issued_at
        ):
            raise RuntimeError(
                "canonical JWT timestamps are outside the expected boundary"
            )
        forbidden = {
            "password",
            "totp",
            "email",
            "provider",
            "subject",
            "signature",
            "account_id",
            "caip_account",
            "credential_data",
        }
        leaked = forbidden.intersection(claims)
        if leaked:
            raise RuntimeError(
                f"authentication protocol data leaked into JWT: {sorted(leaked)}"
            )
        acr = expected_acr if expected_acr is not None else "absent"
        self.scenario.details.append(
            f"HTTP 200 canonical JWT with amr={expected_amr!r}, acr={acr}: PASS"
        )
        return AuthenticatedLogin(token, principal_id, claims, payload)

    def postgres_scalar(self, sql: str) -> str:
        return self._postgresql_query(self._postgresql_pod(), sql)

    @staticmethod
    def verify_persisted_account_state(query) -> dict[str, int]:
        return E2EPostgresChecker.check_counts(
            query,
            {
                "identity_binding_count": (
                    "(SELECT count(*) FROM authguard.iam_principal_identity)",
                    13,
                    None,
                ),
                "credential_count": (
                    "(SELECT count(*) FROM authguard.iam_standalone_credential)",
                    3,
                    None,
                ),
                "social_binding_count": (
                    "(SELECT count(*) FROM authguard.iam_principal_identity WHERE (provider='github' AND issuer='https://github.com' AND subject='987654') OR (provider='google' AND issuer='https://accounts.google.com' AND subject='google-editor-001') OR (provider='wechat' AND issuer='https://open.weixin.qq.com' AND subject='wechat-union-001') OR (provider='qq' AND issuer='https://graph.qq.com' AND subject='qq-open-001'))",
                    4,
                    4,
                ),
                "active_password_count": (
                    "(SELECT count(*) FROM authguard.iam_standalone_credential WHERE kind='password' AND revoked_at IS NULL)",
                    1,
                    None,
                ),
                "active_totp_count": (
                    "(SELECT count(*) FROM authguard.iam_standalone_credential WHERE kind='totp' AND revoked_at IS NULL)",
                    1,
                    None,
                ),
                "active_webauthn_count": (
                    "(SELECT count(*) FROM authguard.iam_standalone_credential WHERE kind='webauthn' AND revoked_at IS NULL)",
                    1,
                    None,
                ),
                "wallet_namespace_count": (
                    "(SELECT count(DISTINCT split_part(subject, ':', 1)) FROM authguard.iam_principal_identity WHERE provider='wallet' AND subject ~ '^(eip155|solana|bip122):[^:]+:.+$')",
                    3,
                    3,
                ),
                "noncanonical_standalone_subject_count": (
                    "(SELECT count(*) FROM authguard.iam_principal_identity WHERE provider='standalone' AND subject NOT LIKE 'local\\_%' ESCAPE '\\')",
                    0,
                    0,
                ),
            },
        )
