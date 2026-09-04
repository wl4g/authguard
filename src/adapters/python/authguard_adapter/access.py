from __future__ import annotations

from contextvars import ContextVar, Token
import os
import time
from typing import Protocol

import grpc
from google.protobuf.wrappers_pb2 import StringValue

from authguard_adapter.model import AccessContext, AccessGrantSet, RequestAccess

GRPC_TARGET_ENV = "AUTHGUARD_GRPC_TARGET"
GRPC_TLS_ENV = "AUTHGUARD_GRPC_TLS"
ACCESS_CONTEXT_HMAC_KEY_ENV = "AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY"


class AccessContextUnavailable(RuntimeError):
    pass


class AccessHeaders(Protocol):
    def header(self, name: str) -> str | None:
        ...


class IAccessContextResolver(Protocol):
    def resolve(self, headers: AccessHeaders) -> RequestAccess | None:
        ...


class ScopeTokenClient(Protocol):
    def resolve_scope(self, token: str) -> str:
        ...


class GrpcScopeTokenClient:
    _METHOD = "/authguard.access.v1.AccessContextService/ResolveScope"

    def __init__(self, target: str, *, secure: bool = False) -> None:
        self._channel = (
            grpc.secure_channel(target, grpc.ssl_channel_credentials())
            if secure
            else grpc.insecure_channel(target)
        )
        self._resolve = self._channel.unary_unary(
            self._METHOD,
            request_serializer=StringValue.SerializeToString,
            response_deserializer=StringValue.FromString,
        )
        from authguard_adapter.util import _log_debug

        _log_debug(
            "authguard.scope_token.grpc.configured",
            resolver_mode="grpc",
            tls=secure,
        )

    def resolve_scope(self, token: str) -> str:
        from authguard_adapter.util import _log_debug, _log_warning, error_category

        started = time.perf_counter()
        _log_debug("authguard.scope_token.grpc.started", resolver_mode="grpc")
        try:
            response: StringValue = self._resolve(StringValue(value=token))
        except grpc.RpcError as error:
            _log_warning(
                "authguard.scope_token.grpc.failed",
                resolver_mode="grpc",
                error_category=error_category(error),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
            raise
        _log_debug(
            "authguard.scope_token.grpc.succeeded",
            resolver_mode="grpc",
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
        return response.value

    def close(self) -> None:
        self._channel.close()

    @classmethod
    def from_env(cls) -> GrpcScopeTokenClient:
        target = os.getenv(GRPC_TARGET_ENV, "").strip()
        if not target:
            raise ValueError(f"{GRPC_TARGET_ENV} is required")
        secure = _parse_bool(os.getenv(GRPC_TLS_ENV, "false"), GRPC_TLS_ENV)
        return cls(target, secure=secure)


class HeaderAccessContextResolver:
    """Verifies and decodes the trusted access context injected by Envoy."""

    def __init__(self, signing_key: str | None = None) -> None:
        if signing_key is not None:
            from authguard_adapter.util import sign_encoded_access_context

            sign_encoded_access_context("probe", signing_key)
        self._signing_key = signing_key

    @classmethod
    def from_env(cls) -> HeaderAccessContextResolver:
        signing_key = os.getenv(ACCESS_CONTEXT_HMAC_KEY_ENV, "")
        if not signing_key:
            raise ValueError(f"{ACCESS_CONTEXT_HMAC_KEY_ENV} is required")
        return cls(signing_key)

    def resolve(self, headers: AccessHeaders) -> RequestAccess | None:
        from authguard_adapter.util import ACCESS_CONTEXT_HEADER, verify_signed_access_context

        encoded = headers.header(ACCESS_CONTEXT_HEADER)
        if not encoded:
            return None
        signing_key = self._signing_key or os.getenv(ACCESS_CONTEXT_HMAC_KEY_ENV, "")
        if not signing_key:
            raise ValueError(f"{ACCESS_CONTEXT_HMAC_KEY_ENV} is required")
        context = verify_signed_access_context(encoded, signing_key)
        return context.request_access()


class GrpcAccessContextResolver:
    """Resolves an opaque request scope token through Authguard gRPC."""

    def __init__(self, client: ScopeTokenClient) -> None:
        self._client = client

    def resolve(self, headers: AccessHeaders) -> RequestAccess | None:
        from authguard_adapter.util import SCOPE_TOKEN_HEADER, decode_access_context

        token = headers.header(SCOPE_TOKEN_HEADER)
        if not token:
            return None
        context = decode_access_context(self._client.resolve_scope(token))
        return context.request_access()

    @classmethod
    def from_env(cls) -> GrpcAccessContextResolver:
        return cls(GrpcScopeTokenClient.from_env())

    def close(self) -> None:
        close = getattr(self._client, "close", None)
        if callable(close):
            close()


_current_access: ContextVar[RequestAccess | None] = ContextVar("authguard_current_access", default=None)


def set_current(grants: AccessGrantSet) -> Token[RequestAccess | None]:
    return set_current_access(RequestAccess.from_grants(grants))


def set_current_access(request_access: RequestAccess) -> Token[RequestAccess | None]:
    from authguard_adapter.util import _log_debug

    _log_debug(
        "authguard.access_context.bound",
        principal_id=request_access.principal_id,
        action=request_access.action,
        allow_count=len(request_access.grants.allow_resource_urns),
        deny_count=len(request_access.grants.deny_resource_urns),
    )
    return _current_access.set(request_access)


def reset_current(token: Token[RequestAccess | None]) -> None:
    from authguard_adapter.util import _log_debug

    current = _current_access.get()
    _current_access.reset(token)
    if current is not None:
        _log_debug(
            "authguard.access_context.cleared",
            principal_id=current.principal_id,
            action=current.action,
        )


def clear_current() -> None:
    from authguard_adapter.util import _log_debug

    current = _current_access.get()
    _current_access.set(None)
    if current is not None:
        _log_debug(
            "authguard.access_context.cleared",
            principal_id=current.principal_id,
            action=current.action,
        )


def get_current() -> AccessGrantSet | None:
    request_access = get_current_access()
    return request_access.grants if request_access is not None else None


def get_current_access() -> RequestAccess | None:
    return _current_access.get()


def require_current() -> AccessGrantSet:
    grants = get_current()
    if grants is None:
        from authguard_adapter.util import _log_debug

        _log_debug("authguard.access_context.required_missing")
        raise AccessContextUnavailable("authguard access context is not available")
    return grants


def require_current_access() -> RequestAccess:
    request_access = get_current_access()
    if request_access is None:
        from authguard_adapter.util import _log_debug

        _log_debug("authguard.access_context.required_missing")
        raise AccessContextUnavailable("authguard access context is not available")
    return request_access


def _parse_bool(value: str, name: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")
