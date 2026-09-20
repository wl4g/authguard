"""AuthN s14 WebAuthn/passkey registration and authentication verifier."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor

from common.deploy.base import AUTHN_BROWSER_HOST
from verifier.authn.other.protocol import AuthnProtocolVerifier
from verifier.authn.password.s13_password_totp import (
    AuthenticatorAppTotpOracle,
    StandaloneFixture,
)


WEBAUTHN_ACR = "urn:authguard:acr:webauthn:uv"
ORIGIN = f"http://{AUTHN_BROWSER_HOST}:8082"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


@dataclass
class VirtualWebAuthnAuthenticator:
    """A real ES256 WebAuthn ceremony oracle with an in-process private key."""

    transport: str
    credential_id: bytes
    private_key: ec.EllipticCurvePrivateKey
    counter: int = 0

    @classmethod
    def create(cls, transport: str) -> "VirtualWebAuthnAuthenticator":
        return cls(transport, os.urandom(32), ec.generate_private_key(ec.SECP256R1()))

    @property
    def credential_key(self) -> str:
        return _b64url(self.credential_id)

    def registration(self, options: dict[str, Any], *, origin: str = ORIGIN) -> dict[str, Any]:
        public_key = options["publicKey"]
        challenge = public_key["challenge"]
        rp_id = public_key["rp"]["id"]
        client_data = json.dumps(
            {"type": "webauthn.create", "challenge": challenge, "origin": origin},
            separators=(",", ":"),
        ).encode()
        numbers = self.private_key.public_key().public_numbers()
        cose_key = cbor.encode(
            {
                1: 2,
                3: -7,
                -1: 1,
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([0x45])
            + self.counter.to_bytes(4, "big")
            + bytes(16)
            + len(self.credential_id).to_bytes(2, "big")
            + self.credential_id
            + cose_key
        )
        attestation = cbor.encode(
            {"fmt": "none", "attStmt": {}, "authData": auth_data}
        )
        return {
            "id": self.credential_key,
            "rawId": self.credential_key,
            "type": "public-key",
            "response": {
                "attestationObject": _b64url(attestation),
                "clientDataJSON": _b64url(client_data),
                "transports": [self.transport],
            },
            "extensions": {},
        }

    def assertion(
        self,
        options: dict[str, Any],
        *,
        counter: int | None = None,
        origin: str = ORIGIN,
        rp_id: str = AUTHN_BROWSER_HOST,
        user_verified: bool = True,
        corrupt_signature: bool = False,
    ) -> dict[str, Any]:
        public_key = options["publicKey"]
        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": public_key["challenge"],
                "origin": origin,
            },
            separators=(",", ":"),
        ).encode()
        counter = self.counter + 1 if counter is None else counter
        flags = 0x01 | (0x04 if user_verified else 0)
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([flags])
            + counter.to_bytes(4, "big")
        )
        signature = self.private_key.sign(
            auth_data + hashlib.sha256(client_data).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
        if corrupt_signature:
            signature = signature[:-1] + bytes([signature[-1] ^ 1])
        return {
            "id": self.credential_key,
            "rawId": self.credential_key,
            "type": "public-key",
            "response": {
                "authenticatorData": _b64url(auth_data),
                "clientDataJSON": _b64url(client_data),
                "signature": _b64url(signature),
                "userHandle": None,
            },
            "extensions": {},
        }


class WebAuthnAuthenticationVerifier(AuthnProtocolVerifier):
    """Exercise platform/security-key ceremonies and their one-time state."""

    def verify(self, standalone: StandaloneFixture) -> None:
        platform = VirtualWebAuthnAuthenticator.create("internal")
        security_key = VirtualWebAuthnAuthenticator.create("usb")
        envoy_service = self._envoy_proxy_service()
        with self._forward_service(envoy_service, 8082) as port:
            self.scenario.step(
                "WebAuthn WA-01: registration is password/MFA gated",
                lambda: self._registration_requires_mfa(port, standalone),
            )
            last_counter = self.scenario.step(
                "WebAuthn WA-02..05: register a UV platform credential and persist public data only",
                lambda: self._register(
                    port, standalone, platform, standalone.last_totp_counter, expected_exclude=[]
                ),
            )
            last_counter = self.scenario.step(
                "WebAuthn WA-06..07: register a second security key with excludeCredentials",
                lambda: self._register(
                    port,
                    standalone,
                    security_key,
                    last_counter,
                    expected_exclude=[platform.credential_key],
                ),
            )
            self.scenario.step(
                "WebAuthn WA-08..09: authenticate to the same Principal and advance counter",
                lambda: self._authenticate(port, standalone, platform),
            )
            self.scenario.step(
                "WebAuthn WA-10..14: reject origin, rpId, UV, signature, and challenge replay",
                lambda: self._negative_ceremonies(port, standalone, platform),
            )
            self.scenario.step(
                "WebAuthn WA-15: reject stale out-of-order assertion counters",
                lambda: self._out_of_order_counter(port, standalone, platform),
            )
            self.scenario.step(
                "WebAuthn WA-16..17: revoked/unknown credentials and protocol data fail closed",
                lambda: self._revocation_contract(port, standalone, platform),
            )

    def _registration_requires_mfa(self, port: int, fixture: StandaloneFixture) -> None:
        # Possessing standalone credentials alone is insufficient: enrollment is
        # an authenticated Principal operation.
        status, payload = self.post(
            port,
            "/auth/webauthn/register/challenge",
            {"login": fixture.login, "password": fixture.password},
        )
        self.expect_error(status, payload, 401, "authentication_failed")
        # A canonical Principal still has to complete the account's configured
        # password + TOTP step-up before WebAuthn registration starts.
        status, payload = self.post(
            port,
            "/auth/webauthn/register/challenge",
            {"login": fixture.login, "password": fixture.password},
            bearer=fixture.access_token,
        )
        self.expect_error(status, payload, 401, "authentication_failed")

    def _register(
        self,
        port: int,
        fixture: StandaloneFixture,
        authenticator: VirtualWebAuthnAuthenticator,
        last_totp_counter: int,
        *,
        expected_exclude: list[str],
    ) -> int:
        counter, code = AuthenticatorAppTotpOracle.next_code(
            fixture.totp_secret, last_totp_counter
        )
        status, challenge = self.post(
            port,
            "/auth/standalone/webauthn/register/challenge",
            {"login": fixture.login, "password": fixture.password, "totp": code},
            bearer=fixture.access_token,
        )
        if status != 200:
            raise RuntimeError(f"WebAuthn registration challenge failed: {status}/{challenge}")
        options = challenge["options"]
        public_key = options["publicKey"]
        excluded = sorted(item["id"] for item in public_key.get("excludeCredentials", []))
        if excluded != sorted(expected_exclude):
            raise RuntimeError(
                f"WebAuthn excludeCredentials mismatch: expected={expected_exclude}, got={excluded}"
            )
        status, enrolled = self.post(
            port,
            "/auth/webauthn/register/verify",
            {
                "challengeId": challenge["challengeId"],
                "credential": authenticator.registration(options),
            },
            bearer=fixture.access_token,
        )
        self.canonical_login(
            status,
            enrolled,
            expected_amr=["pwd", "otp", "webauthn"],
            expected_acr=WEBAUTHN_ACR,
            expected_principal_id=fixture.principal_id,
        )
        replay_status, replay = self.post(
            port,
            "/auth/webauthn/register/verify",
            {
                "challengeId": challenge["challengeId"],
                "credential": authenticator.registration(options),
            },
            bearer=fixture.access_token,
        )
        self.expect_error(replay_status, replay, 400, "invalid_request")
        row = self.postgres_scalar(
            "SELECT kind || '|' || credential_key || '|' || "
            "COALESCE(secret_data, '<null>') || '|' || "
            "jsonb_extract_path_text(credential_data::jsonb, 'cred', 'counter') "
            "FROM iam_standalone_credential "
            f"WHERE kind='webauthn' AND credential_key='{authenticator.credential_key}';"
        )
        if row != f"webauthn|{authenticator.credential_key}|<null>|0":
            raise RuntimeError(f"WebAuthn credential persistence is invalid: {row}")
        return counter

    def _authentication_challenge(self, port: int, login: str) -> dict[str, Any]:
        status, challenge = self.post(
            port,
            "/auth/webauthn/authenticate/challenge",
            {"login": login},
        )
        if status != 200:
            raise RuntimeError(f"WebAuthn authentication challenge failed: {status}/{challenge}")
        return challenge

    def _authenticate(
        self,
        port: int,
        fixture: StandaloneFixture,
        authenticator: VirtualWebAuthnAuthenticator,
    ) -> None:
        challenge = self._authentication_challenge(port, fixture.login)
        authenticator.counter += 1
        status, payload = self.post(
            port,
            "/auth/standalone/webauthn/authenticate/verify",
            {
                "challengeId": challenge["challengeId"],
                "credential": authenticator.assertion(
                    challenge["options"], counter=authenticator.counter
                ),
            },
        )
        self.canonical_login(
            status,
            payload,
            expected_amr=["webauthn"],
            expected_acr=WEBAUTHN_ACR,
            expected_principal_id=fixture.principal_id,
        )
        if self._stored_counter(authenticator) != authenticator.counter:
            raise RuntimeError("WebAuthn signature counter was not durably advanced")

    def _negative_ceremonies(
        self,
        port: int,
        fixture: StandaloneFixture,
        authenticator: VirtualWebAuthnAuthenticator,
    ) -> None:
        variants = (
            {"origin": "https://evil.example"},
            {"rp_id": "evil.example"},
            {"user_verified": False},
            {"corrupt_signature": True},
        )
        for variant in variants:
            challenge = self._authentication_challenge(port, fixture.login)
            credential = authenticator.assertion(
                challenge["options"], counter=authenticator.counter + 1, **variant
            )
            status, payload = self.post(
                port,
                "/auth/webauthn/authenticate/verify",
                {"challengeId": challenge["challengeId"], "credential": credential},
            )
            self.expect_error(status, payload, 401, "authentication_failed")
            replay_status, replay = self.post(
                port,
                "/auth/webauthn/authenticate/verify",
                {"challengeId": challenge["challengeId"], "credential": credential},
            )
            self.expect_error(replay_status, replay, 400, "invalid_request")

    def _out_of_order_counter(
        self,
        port: int,
        fixture: StandaloneFixture,
        authenticator: VirtualWebAuthnAuthenticator,
    ) -> None:
        low = self._authentication_challenge(port, fixture.login)
        high = self._authentication_challenge(port, fixture.login)
        low_counter = authenticator.counter + 1
        high_counter = authenticator.counter + 2
        high_status, high_payload = self.post(
            port,
            "/auth/webauthn/authenticate/verify",
            {
                "challengeId": high["challengeId"],
                "credential": authenticator.assertion(
                    high["options"], counter=high_counter
                ),
            },
        )
        self.canonical_login(
            high_status,
            high_payload,
            expected_amr=["webauthn"],
            expected_acr=WEBAUTHN_ACR,
            expected_principal_id=fixture.principal_id,
        )
        low_status, low_payload = self.post(
            port,
            "/auth/webauthn/authenticate/verify",
            {
                "challengeId": low["challengeId"],
                "credential": authenticator.assertion(
                    low["options"], counter=low_counter
                ),
            },
        )
        self.expect_error(low_status, low_payload, 401, "authentication_failed")
        if self._stored_counter(authenticator) != high_counter:
            raise RuntimeError("WebAuthn counter regressed after an out-of-order assertion")
        authenticator.counter = high_counter

    def _revocation_contract(
        self,
        port: int,
        fixture: StandaloneFixture,
        authenticator: VirtualWebAuthnAuthenticator,
    ) -> None:
        changed = self.postgres_scalar(
            "WITH changed AS (UPDATE iam_standalone_credential "
            "SET revoked_at=CURRENT_TIMESTAMP "
            f"WHERE kind='webauthn' AND credential_key='{authenticator.credential_key}' "
            "RETURNING 1) SELECT COUNT(*) FROM changed;"
        )
        if changed != "1":
            raise RuntimeError("WebAuthn credential revocation fixture update failed")
        challenge = self._authentication_challenge(port, fixture.login)
        active_ids = {
            item["id"]
            for item in challenge["options"]["publicKey"].get("allowCredentials", [])
        }
        if authenticator.credential_key in active_ids:
            raise RuntimeError("revoked WebAuthn credential remained in allowCredentials")
        status, payload = self.post(
            port,
            "/auth/webauthn/authenticate/verify",
            {
                "challengeId": challenge["challengeId"],
                "credential": authenticator.assertion(challenge["options"]),
            },
        )
        self.expect_error(status, payload, 401, "authentication_failed")
        status, payload = self.post(
            port,
            "/auth/webauthn/authenticate/challenge",
            {"login": "unknown-webauthn@example.net"},
        )
        self.expect_error(status, payload, 401, "authentication_failed")
        if self.postgres_scalar(
            "SELECT COUNT(*) FROM iam_standalone_credential "
            "WHERE kind NOT IN ('password','totp','webauthn');"
        ) != "0":
            raise RuntimeError("passkey/authenticator types leaked into credential kind")

    def _stored_counter(self, authenticator: VirtualWebAuthnAuthenticator) -> int:
        value = self.postgres_scalar(
            "SELECT jsonb_extract_path_text(credential_data::jsonb, 'cred', 'counter') "
            "FROM iam_standalone_credential "
            f"WHERE kind='webauthn' AND credential_key='{authenticator.credential_key}';"
        )
        return int(value)
