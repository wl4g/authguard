"""AuthN s13 standalone password and RFC 6238 TOTP verifier."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import os
from urllib import parse
import time

import pyotp

from verifier.authn.other.protocol import AuthenticatedLogin, AuthnProtocolVerifier


@dataclass(frozen=True)
class StandaloneFixture:
    login: str
    password: str
    totp_secret: str
    principal_id: str
    access_token: str
    last_totp_counter: int


class AuthenticatorAppTotpOracle:
    """PyOTP RFC 6238 oracle equivalent to standard authenticator apps."""

    step_seconds = 30
    digits = 6

    @staticmethod
    def assert_rfc6238_compatibility() -> None:
        # RFC 6238 Appendix B SHA-1 vector. Google/Microsoft Authenticator and
        # other standard apps implement the same TOTP construction.
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        generated = pyotp.TOTP(secret, digits=8, interval=30, digest=hashlib.sha1).at(59)
        if generated != "94287082":
            raise RuntimeError(f"PyOTP failed the RFC 6238 SHA-1 vector: {generated}")

    @classmethod
    def counter(cls) -> int:
        return int(time.time()) // cls.step_seconds

    @classmethod
    def code(cls, secret: str, counter: int | None = None) -> str:
        counter = cls.counter() if counter is None else counter
        return pyotp.TOTP(
            secret,
            digits=cls.digits,
            interval=cls.step_seconds,
            digest=hashlib.sha1,
        ).at(counter * cls.step_seconds)

    @classmethod
    def next_code(cls, secret: str, after: int) -> tuple[int, str]:
        candidate = after + 1
        deadline = time.monotonic() + cls.step_seconds + 2
        # The server allows RFC 6238 skew=1. Wait only until the strictly newer
        # counter is inside that window; never reuse an already accepted counter.
        while candidate > cls.counter() + 1:
            if time.monotonic() >= deadline:
                raise RuntimeError("timed out waiting for the next RFC 6238 counter")
            time.sleep(0.2)
        return candidate, cls.code(secret, candidate)


class PasswordTotpAuthenticationVerifier(AuthnProtocolVerifier):
    """Exercise credential lifecycle, replay resistance, and account linking."""

    def verify(self, github: AuthenticatedLogin) -> StandaloneFixture:
        unique = f"r{self.context.round_number}-{os.urandom(5).hex()}"
        login = f"standalone-{unique}@example.net"
        password = "correct horse battery staple"
        envoy_service = self._envoy_proxy_service()
        with self._forward_service(envoy_service, 8082) as port:
            registered = self.scenario.step(
                "Password ST-01..03: register a stable standalone identity and Argon2id credential",
                lambda: self._register_and_inspect(port, login, password),
            )
            self.scenario.step(
                "Password ST-04..07: repeat login, aliases, policy, and indistinguishable failures",
                lambda: self._password_contract(port, login, password, registered.principal_id),
            )
            self.scenario.step(
                "Password ST-08: concurrent duplicate registration is atomic and orphan-free",
                lambda: self._concurrent_registration(port, unique),
            )
            self.scenario.step(
                "Password ST-09..10: equal email-shaped identifiers never auto-merge",
                lambda: self._no_identifier_merge(port, unique, registered.principal_id),
            )
            self.scenario.step(
                "Password ST-11: explicit standalone link requires a canonical bearer",
                lambda: self._explicit_link(port, unique, github),
            )
            secret, enrollment_counter = self.scenario.step(
                "TOTP ST-12..14: password-gated enrollment uses a standard otpauth secret",
                lambda: self._enroll_totp(port, login, password, registered.principal_id),
            )
            last_counter, mfa_login = self.scenario.step(
                "TOTP ST-15..17: enforce MFA and atomically reject replay/concurrent reuse",
                lambda: self._verify_totp_login(
                    port,
                    login,
                    password,
                    secret,
                    enrollment_counter,
                    registered.principal_id,
                ),
            )
            self.scenario.step(
                "Password ST-18: revoked credentials fail closed",
                lambda: self._revocation_contract(port, unique, password),
            )
        return StandaloneFixture(
            login,
            password,
            secret,
            registered.principal_id,
            mfa_login.access_token,
            last_counter,
        )

    def _register_and_inspect(
        self, port: int, login: str, password: str
    ) -> AuthenticatedLogin:
        status, payload = self.post(
            port,
            "/auth/standalone/register",
            {"login": login, "password": password, "displayName": "Standalone E2E"},
        )
        registered = self.canonical_login(status, payload, expected_amr=["pwd"])
        row = self.postgres_scalar(
            "SELECT i.provider || '|' || i.issuer || '|' || i.subject || '|' || "
            "c.kind || '|' || c.credential_key || '|' || c.secret_data "
            "FROM iam_standalone_credential c JOIN iam_principal_identity i "
            "ON (i.provider, i.issuer, i.subject) = "
            "(c.identity_provider, c.identity_issuer, c.identity_subject) "
            f"WHERE c.kind='password' AND c.credential_key='{self._sql(login)}';"
        )
        provider, issuer, subject, kind, key, password_hash = row.split("|", 5)
        if (
            provider != "standalone"
            or issuer != "urn:authguard:e2e:standalone"
            or not subject.startswith("local_")
            or subject == login
            or kind != "password"
            or key != login
            or not password_hash.startswith("$argon2id$v=19$")
            or password in password_hash
        ):
            raise RuntimeError("standalone identity or Argon2id PHC persistence is invalid")
        return registered

    def _password_contract(
        self, port: int, login: str, password: str, principal_id: str
    ) -> None:
        status, payload = self.post(
            port,
            "/auth/login",
            {"login": f"  {login.upper()}  ", "password": password},
        )
        self.canonical_login(
            status,
            payload,
            expected_amr=["pwd"],
            expected_principal_id=principal_id,
        )
        failures = []
        for candidate_login, candidate_password in (
            (login, "definitely-wrong-password"),
            (f"missing-{login}", "definitely-wrong-password"),
        ):
            status, payload = self.post(
                port,
                "/auth/standalone/login",
                {"login": candidate_login, "password": candidate_password},
            )
            failures.append((status, payload.get("code"), payload.get("message")))
        if failures[0] != failures[1] or failures[0][:2] != (401, "authentication_failed"):
            raise RuntimeError(f"unknown-login oracle differs from wrong password: {failures}")
        status, payload = self.post(
            port,
            "/auth/standalone/register",
            {"login": login, "password": password, "displayName": "duplicate"},
        )
        self.expect_error(status, payload, 409, "conflict")
        status, _ = self.post(
            port,
            "/auth/register",
            {
                "login": f"invalid-{login}",
                "password": "short",
                "displayName": "invalid",
                "signatureValid": True,
            },
        )
        if status != 422:
            raise RuntimeError(f"standalone unknown fields must be rejected, got HTTP {status}")

    def _concurrent_registration(self, port: int, unique: str) -> None:
        login = f"concurrent-{unique}@example.net"
        marker = f"Concurrent {unique}"
        body = {
            "login": login,
            "password": "concurrent-registration-password",
            "displayName": marker,
        }
        with ThreadPoolExecutor(max_workers=4) as executor:
            responses = list(
                executor.map(
                    lambda _: self.post(port, "/auth/standalone/register", body), range(4)
                )
            )
        statuses = sorted(status for status, _ in responses)
        if statuses.count(200) != 1 or statuses.count(409) != 3:
            raise RuntimeError(f"duplicate registration was not atomic: {statuses}")
        counts = self.postgres_scalar(
            "SELECT "
            "COUNT(DISTINCT i.principal_id) || '|' || COUNT(*) "
            "FROM iam_principal_identity i "
            "WHERE i.provider='standalone' "
            f"AND i.claims->>'display_name'='{self._sql(marker)}';"
        )
        if counts != "1|1":
            raise RuntimeError(f"duplicate registration left orphan identity state: {counts}")

    def _no_identifier_merge(self, port: int, unique: str, first_principal: str) -> None:
        status, payload = self.post(
            port,
            "/auth/standalone/register",
            {
                "login": f"separate-{unique}@example.net",
                "password": "separate-account-password",
                "displayName": "Standalone E2E",
            },
        )
        second = self.canonical_login(status, payload, expected_amr=["pwd"])
        if second.principal_id == first_principal:
            raise RuntimeError("equal profile display names auto-merged standalone identities")

    def _explicit_link(
        self, port: int, unique: str, github: AuthenticatedLogin
    ) -> None:
        body = {
            "login": f"linked-{unique}@example.net",
            "password": "explicitly-linked-password",
            "displayName": "Explicit standalone link",
        }
        status, payload = self.post(port, "/auth/standalone/register", body)
        if status != 200:
            # The unauthenticated registration consumes this identifier, so use a fresh one
            # for the actual proof. This branch exists only to make the bearer requirement clear.
            raise RuntimeError(f"standalone first-login precondition failed: {status}/{payload}")
        unlinked = self.canonical_login(status, payload, expected_amr=["pwd"])
        if unlinked.principal_id == github.principal_id:
            raise RuntimeError("standalone identity auto-linked without explicit authorization")

        linked_body = {
            "login": f"linked-proof-{unique}@example.net",
            "password": "explicitly-linked-password",
            "displayName": "Explicit standalone link proof",
        }
        status, payload = self.post(
            port,
            "/auth/standalone/register",
            linked_body,
            bearer=github.access_token,
        )
        self.canonical_login(
            status,
            payload,
            expected_amr=["pwd"],
            expected_principal_id=github.principal_id,
        )

    def _enroll_totp(
        self, port: int, login: str, password: str, principal_id: str
    ) -> tuple[str, int]:
        AuthenticatorAppTotpOracle.assert_rfc6238_compatibility()
        status, payload = self.post(
            port,
            "/auth/totp/challenge",
            {"login": login, "password": "wrong-password"},
        )
        self.expect_error(status, payload, 401, "authentication_failed")
        status, challenge = self.post(
            port,
            "/auth/standalone/totp/challenge",
            {"login": login, "password": password},
        )
        if status != 200:
            raise RuntimeError(f"TOTP enrollment challenge failed: {status}/{challenge}")
        secret = challenge.get("secret", "")
        otpauth_uri = challenge.get("otpauthUri", "")
        uri = parse.urlsplit(otpauth_uri)
        query = parse.parse_qs(uri.query)
        try:
            authenticator = pyotp.parse_uri(otpauth_uri)
        except ValueError as error:
            raise RuntimeError("TOTP enrollment URI is not accepted by PyOTP") from error
        # Google Authenticator's Key URI format defines SHA1/6 digits/30 seconds
        # as defaults, and conforming encoders may omit those query parameters.
        algorithm = query.get("algorithm", ["SHA1"])
        digits = query.get("digits", ["6"])
        period = query.get("period", ["30"])
        if (
            uri.scheme != "otpauth"
            or uri.netloc != "totp"
            or query.get("issuer") != ["AuthGuard E2E"]
            or algorithm != ["SHA1"]
            or digits != ["6"]
            or period != ["30"]
            or query.get("secret") != [secret]
            or not secret
            or not isinstance(authenticator, pyotp.TOTP)
            or authenticator.secret != secret
            or authenticator.issuer != "AuthGuard E2E"
            or authenticator.digits != 6
            or authenticator.interval != 30
            or authenticator.digest().name.lower() != "sha1"
        ):
            raise RuntimeError("TOTP enrollment is not RFC 6238/otpauth compatible")
        current = AuthenticatorAppTotpOracle.counter()
        counter = (
            current - 1
            if int(time.time()) % AuthenticatorAppTotpOracle.step_seconds > 2
            else current
        )
        status, enrolled = self.post(
            port,
            "/auth/totp/verify",
            {
                "challengeId": challenge["challengeId"],
                "code": AuthenticatorAppTotpOracle.code(secret, counter),
            },
        )
        self.canonical_login(
            status,
            enrolled,
            expected_amr=["pwd", "otp"],
            expected_principal_id=principal_id,
        )
        replay_status, replay = self.post(
            port,
            "/auth/standalone/totp/verify",
            {
                "challengeId": challenge["challengeId"],
                "code": AuthenticatorAppTotpOracle.code(secret, counter),
            },
        )
        self.expect_error(replay_status, replay, 400, "invalid_request")
        row = self.postgres_scalar(
            "SELECT secret_data || '|' || "
            "jsonb_extract_path_text(credential_data::jsonb, 'lastCounter') "
            "FROM iam_standalone_credential "
            f"WHERE kind='totp' AND identity_subject=(SELECT subject FROM iam_principal_identity WHERE principal_id='{self._sql(principal_id)}' AND provider='standalone');"
        )
        encrypted, stored_counter = row.split("|", 1)
        if not encrypted.startswith("v1:") or secret in encrypted or int(stored_counter) != counter:
            raise RuntimeError("TOTP secret encryption or replay counter persistence is invalid")
        return secret, counter

    def _verify_totp_login(
        self,
        port: int,
        login: str,
        password: str,
        secret: str,
        previous_counter: int,
        principal_id: str,
    ) -> tuple[int, AuthenticatedLogin]:
        status, payload = self.post(
            port,
            "/auth/standalone/login",
            {"login": login, "password": password},
        )
        self.expect_error(status, payload, 401, "authentication_failed")
        counter, code = AuthenticatorAppTotpOracle.next_code(secret, previous_counter)
        wrong_code = code[:-1] + str((int(code[-1]) + 1) % 10)
        status, payload = self.post(
            port,
            "/auth/login",
            {"login": login, "password": password, "totp": wrong_code},
        )
        self.expect_error(status, payload, 401, "authentication_failed")
        body = {"login": login, "password": password, "totp": code}
        with ThreadPoolExecutor(max_workers=2) as executor:
            responses = list(executor.map(lambda _: self.post(port, "/auth/login", body), range(2)))
        successes = [(status, payload) for status, payload in responses if status == 200]
        failures = [(status, payload) for status, payload in responses if status != 200]
        if len(successes) != 1 or len(failures) != 1:
            raise RuntimeError(f"TOTP counter was not consumed atomically: {responses}")
        self.expect_error(failures[0][0], failures[0][1], 401, "authentication_failed")
        authenticated = self.canonical_login(
            successes[0][0],
            successes[0][1],
            expected_amr=["pwd", "otp"],
            expected_principal_id=principal_id,
        )
        status, replay = self.post(port, "/auth/login", body)
        self.expect_error(status, replay, 401, "authentication_failed")
        return counter, authenticated

    def _revocation_contract(self, port: int, unique: str, password: str) -> None:
        login = f"revoked-{unique}@example.net"
        status, payload = self.post(
            port,
            "/auth/standalone/register",
            {"login": login, "password": password, "displayName": "Revoked credential"},
        )
        self.canonical_login(status, payload, expected_amr=["pwd"])
        changed = self.postgres_scalar(
            "WITH changed AS (UPDATE iam_standalone_credential "
            "SET revoked_at=CURRENT_TIMESTAMP "
            f"WHERE kind='password' AND credential_key='{self._sql(login)}' RETURNING 1) "
            "SELECT COUNT(*) FROM changed;"
        )
        if changed != "1":
            raise RuntimeError("password revocation fixture update failed")
        status, payload = self.post(
            port, "/auth/login", {"login": login, "password": password}
        )
        self.expect_error(status, payload, 401, "authentication_failed")

    @staticmethod
    def _sql(value: str) -> str:
        return value.replace("'", "''")
