from __future__ import annotations

import base64
import json
import os
import unittest
from typing import Any
from unittest.mock import patch

from authguard_adapter import access
from authguard_adapter.access import (
    ACCESS_CONTEXT_HMAC_KEY_ENV,
    HeaderAccessContextResolver,
    GRPC_TARGET_ENV,
    GRPC_TLS_ENV,
    GrpcScopeTokenClient,
    GrpcAccessContextResolver,
)
from authguard_adapter.filter import AccessFilter, AccessMiddleware
from authguard_adapter.model import AccessContext, RequestAccess
from authguard_adapter.util import (
    ACCESS_CONTEXT_HEADER,
    SCOPE_TOKEN_HEADER,
    encode_access_context,
    sign_access_context,
    sign_encoded_access_context,
)

TEST_SIGNING_KEY = "test-access-context-hmac-key-32-bytes-minimum"


class StaticScopeTokenClient:
    def __init__(self, encoded_context: str) -> None:
        self.encoded_context = encoded_context
        self.token: str | None = None

    def resolve_scope(self, token: str) -> str:
        self.token = token
        return self.encoded_context


class FailingScopeTokenClient:
    def resolve_scope(self, _token: str) -> str:
        raise RuntimeError("scope service unavailable")


class UnexpectedScopeTokenClient:
    def resolve_scope(self, _token: str) -> str:
        raise AssertionError("scope service must not be called")


class PythonAdapterFilterTest(unittest.TestCase):
    def setUp(self) -> None:
        self._environment = patch.dict(
            os.environ, {ACCESS_CONTEXT_HMAC_KEY_ENV: TEST_SIGNING_KEY}, clear=False
        )
        self._environment.start()

    def tearDown(self) -> None:
        access.clear_current()
        self._environment.stop()

    def test_header_context_resolver_sets_request_access(self) -> None:
        with AccessFilter().enter_headers(signed_context(), None) as scope:
            self.assert_authenticated(scope.request_access)

        self.assertIsNone(access.get_current_access())

    def test_grpc_context_resolver_resolves_opaque_token(self) -> None:
        client = StaticScopeTokenClient(encode_access_context(sample_context()))
        access_filter = AccessFilter(GrpcAccessContextResolver(client))

        with access_filter.enter_headers(None, "ags_scope") as scope:
            self.assert_authenticated(scope.request_access)

        self.assertEqual("ags_scope", client.token)
        self.assertIsNone(access.get_current_access())

    def test_missing_access_headers_remain_unauthenticated(self) -> None:
        access.set_current_access(sample_context().request_access())

        with AccessFilter().enter_headers(None, None) as scope:
            self.assertFalse(scope.authenticated)
            self.assertIsNone(access.get_current_access())

    def test_malformed_direct_context_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid signed Authguard access context"):
            AccessFilter().enter_headers("not-base64!", None)

        self.assertIsNone(access.get_current_access())

    def test_unsupported_direct_context_version_fails_closed(self) -> None:
        payload = context_payload(sample_context())
        payload["version"] = 2

        with self.assertRaisesRegex(ValueError, "unsupported access context version: 2"):
            AccessFilter().enter_headers(sign_unchecked(payload), None)

        self.assertIsNone(access.get_current_access())

    def test_expired_direct_context_fails_closed(self) -> None:
        payload = context_payload(sample_context())
        payload["issued_at_epoch_seconds"] = 1
        payload["expires_at_epoch_seconds"] = 2

        with self.assertRaisesRegex(ValueError, "access context has expired"):
            AccessFilter().enter_headers(sign_unchecked(payload), None)

        self.assertIsNone(access.get_current_access())

    def test_conflicting_context_and_token_headers_fail_closed(self) -> None:
        with self.assertRaisesRegex(PermissionError, "both Authguard context"):
            AccessFilter().enter_headers(signed_context(), "ags_scope")

        self.assertIsNone(access.get_current_access())

    def test_scope_resolver_failure_fails_closed(self) -> None:
        access_filter = AccessFilter(GrpcAccessContextResolver(FailingScopeTokenClient()))

        with self.assertRaisesRegex(RuntimeError, "scope service unavailable"):
            access_filter.enter_headers(None, "ags_scope")

        self.assertIsNone(access.get_current_access())

    def test_scope_token_without_request_resolver_fails_closed(self) -> None:
        with self.assertRaisesRegex(PermissionError, "no resolver is configured"):
            AccessFilter().enter_headers(None, "ags_scope")

        self.assertIsNone(access.get_current_access())

    def test_malformed_resolved_context_fails_closed(self) -> None:
        access_filter = AccessFilter(
            GrpcAccessContextResolver(StaticScopeTokenClient("not-base64!"))
        )

        with self.assertRaisesRegex(ValueError, "invalid Authguard access context"):
            access_filter.enter_headers(None, "ags_scope")

        self.assertIsNone(access.get_current_access())

    def test_direct_context_does_not_call_scope_service(self) -> None:
        access_filter = AccessFilter(
            HeaderAccessContextResolver(TEST_SIGNING_KEY),
            GrpcAccessContextResolver(UnexpectedScopeTokenClient())
        )

        with access_filter.enter_headers(signed_context(), None) as scope:
            self.assert_authenticated(scope.request_access)

    def test_second_entry_does_not_reuse_previous_request_access(self) -> None:
        first = AccessFilter().enter_headers(signed_context(), None)
        self.assertIsNotNone(access.get_current_access())

        with AccessFilter().enter_headers(None, None) as second:
            self.assertFalse(second.authenticated)
            self.assertIsNone(access.get_current_access())

        first.close()

    def test_framework_adapter_scopes_direct_context_to_request(self) -> None:
        captured: RequestAccess | None = None

        def app(_environ: dict[str, Any], start_response: Any) -> list[bytes]:
            nonlocal captured
            captured = access.require_current_access()
            start_response("200 OK", [])
            return [b"ok"]

        middleware = AccessMiddleware(app)
        environ = {"HTTP_X_AUTHGUARD_CONTEXT": signed_context()}

        response = list(middleware(environ, lambda _status, _headers: None))

        self.assertEqual([b"ok"], response)
        self.assert_authenticated(captured, require_current=False)
        self.assertIsNone(access.get_current_access())

    def test_framework_adapter_rejects_missing_access_context(self) -> None:
        app_called = False
        statuses: list[str] = []

        def app(_environ: dict[str, Any], _start_response: Any) -> list[bytes]:
            nonlocal app_called
            app_called = True
            return [b"unexpected"]

        response = list(
            AccessMiddleware(app)({}, lambda status, _headers: statuses.append(status))
        )

        self.assertEqual([b"Unauthorized"], response)
        self.assertEqual(["401 Unauthorized"], statuses)
        self.assertFalse(app_called)
        self.assertIsNone(access.get_current_access())

    def test_framework_adapter_resolves_scope_token(self) -> None:
        captured: RequestAccess | None = None
        client = StaticScopeTokenClient(encode_access_context(sample_context()))

        def app(_environ: dict[str, Any], start_response: Any) -> list[bytes]:
            nonlocal captured
            captured = access.require_current_access()
            start_response("200 OK", [])
            return [b"ok"]

        middleware = AccessMiddleware(app, GrpcAccessContextResolver(client))
        environ = {"HTTP_X_AUTHGUARD_SCOPE_TOKEN": "ags_scope"}

        self.assertEqual(
            [b"ok"], list(middleware(environ, lambda _status, _headers: None))
        )
        self.assert_authenticated(captured, require_current=False)
        self.assertEqual("ags_scope", client.token)

    def test_grpc_target_configuration_uses_standard_environment_names(self) -> None:
        self.assertEqual("AUTHGUARD_GRPC_TARGET", GRPC_TARGET_ENV)
        self.assertEqual("AUTHGUARD_GRPC_TLS", GRPC_TLS_ENV)

    def test_grpc_client_accepts_explicit_internal_target_without_connecting(self) -> None:
        client = GrpcScopeTokenClient(
            "authguard.authguard.svc.cluster.local:8080", secure=False
        )
        client.close()

    def test_grpc_client_initializes_from_environment_without_connecting(self) -> None:
        with patch.dict(
            os.environ,
            {
                GRPC_TARGET_ENV: "authguard.authguard.svc.cluster.local:8080",
                GRPC_TLS_ENV: "false",
            },
            clear=False,
        ):
            client = GrpcScopeTokenClient.from_env()
        client.close()

    def test_unsigned_direct_context_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid signed Authguard access context"):
            AccessFilter().enter_headers(encode_access_context(sample_context()), None)

    def test_tampered_direct_context_fails_closed(self) -> None:
        tampered = signed_context().replace("agctx1.", "agctx1.A", 1)
        with self.assertRaisesRegex(ValueError, "signature"):
            AccessFilter().enter_headers(tampered, None)

    def test_direct_context_signed_with_different_key_fails_closed(self) -> None:
        signed = sign_access_context(
            sample_context(), "different-access-context-hmac-key-32-bytes-minimum"
        )
        with self.assertRaisesRegex(ValueError, "signature"):
            AccessFilter().enter_headers(signed, None)

    def test_signing_key_configuration_uses_standard_environment_name(self) -> None:
        self.assertEqual("AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY", ACCESS_CONTEXT_HMAC_KEY_ENV)

    def assert_authenticated(
        self, request_access: RequestAccess | None, *, require_current: bool = True
    ) -> None:
        self.assertIsNotNone(request_access)
        assert request_access is not None
        self.assertEqual("revenue-analyst", request_access.principal_id)
        self.assertEqual("customer-growth.job.read", request_access.action)
        if require_current:
            self.assertEqual(request_access, access.require_current_access())


def context_payload(context: AccessContext) -> dict[str, Any]:
    return {
        "version": context.version,
        "principal_id": context.principal_id,
        "action": context.action,
        "resource_urn": context.resource_urn,
        "allow_resource_urns": list(context.allow_resource_urns),
        "deny_resource_urns": list(context.deny_resource_urns),
        "policy_revision": context.policy_revision,
        "issued_at_epoch_seconds": context.issued_at_epoch_seconds,
        "expires_at_epoch_seconds": context.expires_at_epoch_seconds,
    }


def encode_unchecked(payload: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()


def sign_unchecked(payload: dict[str, Any]) -> str:
    return sign_encoded_access_context(encode_unchecked(payload), TEST_SIGNING_KEY)


def signed_context() -> str:
    return sign_access_context(sample_context(), TEST_SIGNING_KEY)


def sample_context() -> AccessContext:
    return AccessContext.active(
        "revenue-analyst",
        "customer-growth.job.read",
        "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score",
        (
            "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/*",
        ),
        (
            "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/vip-retention-risk-audit",
        ),
    )


if __name__ == "__main__":
    unittest.main()
