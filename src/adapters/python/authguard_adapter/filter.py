from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
import time
from typing import Any

import grpc

from authguard_adapter.access import (
    AccessHeaders,
    GrpcAccessContextResolver,
    HeaderAccessContextResolver,
    IAccessContextResolver,
    clear_current,
    reset_current,
    set_current_access,
)
from authguard_adapter.model import AccessGrantSet, RequestAccess
from authguard_adapter.util import (
    ACCESS_CONTEXT_HEADER,
    REQUEST_ID_HEADER,
    SCOPE_TOKEN_HEADER,
    _log_debug,
    error_category,
    safe_log_string,
)

StartResponse = Callable[[str, list[tuple[str, str]], Any], Any]
WsgiApp = Callable[[dict[str, Any], StartResponse], Iterable[bytes]]


@dataclass
class AccessFilterScope:
    authenticated: bool
    grants: AccessGrantSet | None
    request_access: RequestAccess | None = None
    _context_token: Any = None
    _closed: bool = False

    def close(self) -> None:
        if self._closed:
            return
        if self._context_token is None:
            clear_current()
        else:
            reset_current(self._context_token)
        self._closed = True

    def __enter__(self) -> AccessFilterScope:
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
        self.close()


class AccessFilter:
    def __init__(self, *resolvers: IAccessContextResolver) -> None:
        self._resolvers: tuple[IAccessContextResolver, ...] = tuple(resolvers) or (
            HeaderAccessContextResolver(),
        )

    def enter(self, request: AccessHeaders) -> AccessFilterScope:
        clear_current()
        direct_context_present = bool(request.header(ACCESS_CONTEXT_HEADER))
        scope_token_present = bool(request.header(SCOPE_TOKEN_HEADER))
        request_id = safe_log_string(request.header(REQUEST_ID_HEADER))
        _log_debug(
            "authguard.access_filter.started",
            request_id=request_id,
            direct_context_present=direct_context_present,
            scope_token_present=scope_token_present,
            resolver_count=len(self._resolvers),
        )
        if direct_context_present and scope_token_present:
            _log_debug(
                "authguard.access_filter.rejected",
                request_id=request_id,
                reason="conflicting_headers",
            )
            raise PermissionError("both Authguard context and scope token headers are present")
        for resolver in self._resolvers:
            try:
                request_access = resolver.resolve(request)
            except (RuntimeError, ValueError, PermissionError, grpc.RpcError) as error:
                _log_debug(
                    "authguard.access_filter.rejected",
                    request_id=request_id,
                    resolver_mode=_resolver_mode(resolver),
                    reason="resolver_error",
                    error_category=error_category(error),
                )
                raise
            if request_access is not None:
                token = set_current_access(request_access)
                _log_debug(
                    "authguard.access_filter.authenticated",
                    request_id=request_id,
                    resolver_mode=_resolver_mode(resolver),
                    principal_id=request_access.principal_id,
                    action=request_access.action,
                    allow_count=len(request_access.grants.allow_resource_urns),
                    deny_count=len(request_access.grants.deny_resource_urns),
                )
                return AccessFilterScope(True, request_access.grants, request_access, token)
        if scope_token_present:
            _log_debug(
                "authguard.access_filter.rejected",
                request_id=request_id,
                reason="scope_resolver_unavailable",
            )
            raise PermissionError("no resolver is configured for the Authguard scope token")
        _log_debug("authguard.access_filter.unauthenticated", request_id=request_id)
        return AccessFilterScope(False, None)

    def enter_headers(
        self, encoded_access_context: str | None, scope_token: str | None
    ) -> AccessFilterScope:
        return self.enter(
            _MappingAccessHeaders(
                {
                    ACCESS_CONTEXT_HEADER: encoded_access_context,
                    SCOPE_TOKEN_HEADER: scope_token,
                }
            )
        )


class AccessMiddleware:
    def __init__(self, app: WsgiApp, *resolvers: IAccessContextResolver) -> None:
        self._app = app
        self._access_filter = AccessFilter(*resolvers)

    def __call__(self, environ: dict[str, Any], start_response: StartResponse) -> Iterable[bytes]:
        started = time.perf_counter()
        request_id = safe_log_string(_WsgiAccessRequest(environ).header(REQUEST_ID_HEADER))
        http_method = safe_log_string(str(environ.get("REQUEST_METHOD", "")))
        try:
            scope = self._access_filter.enter(_WsgiAccessRequest(environ))
        except (RuntimeError, ValueError, PermissionError, grpc.RpcError) as error:
            _log_debug(
                "authguard.http_filter.rejected",
                request_id=request_id,
                http_method=http_method,
                reason="invalid_access_context",
                error_category=error_category(error),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
            start_response("401 Unauthorized", [("Content-Type", "text/plain")])
            return [b"Unauthorized"]
        if not scope.authenticated:
            scope.close()
            _log_debug(
                "authguard.http_filter.rejected",
                request_id=request_id,
                http_method=http_method,
                reason="access_context_missing",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
            start_response("401 Unauthorized", [("Content-Type", "text/plain")])
            return [b"Unauthorized"]
        assert scope.request_access is not None
        _log_debug(
            "authguard.http_filter.accepted",
            request_id=request_id,
            http_method=http_method,
            principal_id=scope.request_access.principal_id,
            action=scope.request_access.action,
        )
        try:
            response = self._app(environ, start_response)
            return _ScopedIterable(
                response,
                scope,
                lambda: _log_debug(
                    "authguard.http_filter.completed",
                    request_id=request_id,
                    http_method=http_method,
                    duration_ms=int((time.perf_counter() - started) * 1000),
                ),
            )
        except Exception:
            scope.close()
            raise


def _resolver_mode(resolver: IAccessContextResolver) -> str:
    if isinstance(resolver, HeaderAccessContextResolver):
        return "header"
    if isinstance(resolver, GrpcAccessContextResolver):
        return "grpc"
    return "custom"


class _MappingAccessHeaders:
    def __init__(self, values: dict[str, str | None]) -> None:
        self._values = values

    def header(self, name: str) -> str | None:
        return self._values.get(name)


class _WsgiAccessRequest:
    def __init__(self, environ: dict[str, Any]) -> None:
        self._environ = environ

    def header(self, name: str) -> str | None:
        value = self._environ.get("HTTP_" + name.upper().replace("-", "_"))
        return str(value) if value is not None else None


class _ScopedIterable:
    def __init__(
        self,
        response: Iterable[bytes],
        scope: AccessFilterScope,
        on_close: Callable[[], None],
    ) -> None:
        self._response = response
        self._scope = scope
        self._on_close = on_close

    def __iter__(self) -> Iterable[bytes]:
        try:
            yield from self._response
        finally:
            close = getattr(self._response, "close", None)
            if callable(close):
                close()
            self._scope.close()
            self._on_close()
