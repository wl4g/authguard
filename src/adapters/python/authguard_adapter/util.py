from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import time
from collections.abc import Sequence
from typing import Any

from authguard_adapter.access import require_current, require_current_access
from authguard_adapter.model import (
    ACCESS_CONTEXT_VERSION,
    AccessContext,
    RequestAccess,
    ResourceSqlMapping,
    SegmentMap,
    SqlScope,
    UrnPattern,
)

ACCESS_CONTEXT_HEADER = "x-authguard-context"
SCOPE_TOKEN_HEADER = "x-authguard-scope-token"
_SIGNED_CONTEXT_PREFIX = "agctx1"
_MIN_SIGNING_KEY_BYTES = 32
REQUEST_ID_HEADER = "x-request-id"

_DEFAULT_LOGGER = logging.getLogger("authguard.adapter")
if not any(isinstance(handler, logging.NullHandler) for handler in _DEFAULT_LOGGER.handlers):
    _DEFAULT_LOGGER.addHandler(logging.NullHandler())
_LOGGER = _DEFAULT_LOGGER


def configure_logger(logger: logging.Logger | None) -> None:
    """Install an application logger; pass ``None`` to disable adapter logging."""

    global _LOGGER
    if logger is None:
        disabled = logging.getLogger("authguard.adapter.disabled")
        disabled.handlers = [logging.NullHandler()]
        disabled.propagate = False
        _LOGGER = disabled
    else:
        _LOGGER = logger


def reset_logger() -> None:
    """Restore the standard ``authguard.adapter`` logging facade."""

    global _LOGGER
    _LOGGER = _DEFAULT_LOGGER


def error_category(error: BaseException | None) -> str:
    """Return an exception class name without including its potentially sensitive message."""

    return type(error).__name__ if error is not None else "unknown"


def safe_log_string(value: str | None) -> str:
    """Bound identifiers and remove control characters before logging."""

    if value is None:
        return "none"
    return "".join("_" if ord(character) < 32 or ord(character) == 127 else character for character in value)[:128]


def _log_debug(event: str, **fields: Any) -> None:
    _log(logging.DEBUG, event, fields)


def _log_warning(event: str, **fields: Any) -> None:
    _log(logging.WARNING, event, fields)


def _log(level: int, event: str, fields: dict[str, Any]) -> None:
    if not _LOGGER.isEnabledFor(level):
        return
    safe_fields = {
        key: safe_log_string(value) if isinstance(value, str) or value is None else value
        for key, value in fields.items()
    }
    rendered = " ".join(f"{key}={value}" for key, value in safe_fields.items())
    message = f"event={event}" + (f" {rendered}" if rendered else "")
    _LOGGER.log(
        level,
        message,
        extra={"authguard_event": event, "authguard_fields": safe_fields},
    )


def encode_access_context(access_context: AccessContext) -> str:
    validate_access_context(access_context)
    payload = {
        "version": access_context.version,
        "principal_id": access_context.principal_id,
        "action": access_context.action,
        "resource_urn": access_context.resource_urn,
        "allow_resource_urns": list(access_context.allow_resource_urns),
        "deny_resource_urns": list(access_context.deny_resource_urns),
        "policy_revision": access_context.policy_revision,
        "issued_at_epoch_seconds": access_context.issued_at_epoch_seconds,
        "expires_at_epoch_seconds": access_context.expires_at_epoch_seconds,
    }
    return base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()


def decode_access_context(encoded: str) -> AccessContext:
    started = time.perf_counter()
    try:
        context = _decode_access_context(encoded)
    except ValueError as error:
        _log_debug(
            "authguard.access_context.decode.failed",
            error_category=error_category(error),
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
        raise
    _log_debug(
        "authguard.access_context.decode.succeeded",
        principal_id=context.principal_id,
        action=context.action,
        allow_count=len(context.allow_resource_urns),
        deny_count=len(context.deny_resource_urns),
        policy_revision=context.policy_revision,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
    return context


def _decode_access_context(encoded: str) -> AccessContext:
    try:
        padding = "=" * (-len(encoded) % 4)
        raw = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
        payload: Any = json.loads(raw)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid Authguard access context") from error
    if not isinstance(payload, dict) or payload.get("version") != ACCESS_CONTEXT_VERSION:
        version = payload.get("version") if isinstance(payload, dict) else None
        raise ValueError(f"unsupported access context version: {version}")
    try:
        allow = _string_tuple(payload["allow_resource_urns"])
        deny = _string_tuple(payload["deny_resource_urns"])
        context = AccessContext(
            version=payload["version"],
            principal_id=_string(_aliased_field(payload, "principal_id", "subject_id")),
            action=_string(payload["action"]),
            resource_urn=_string(payload["resource_urn"]),
            allow_resource_urns=allow,
            deny_resource_urns=deny,
            policy_revision=_integer(
                _aliased_field(payload, "policy_revision", "policy_version")
            ),
            issued_at_epoch_seconds=_integer(payload["issued_at_epoch_seconds"]),
            expires_at_epoch_seconds=_integer(payload["expires_at_epoch_seconds"]),
        )
        validate_access_context(context)
        return context
    except (KeyError, TypeError) as error:
        raise ValueError("invalid Authguard access context fields") from error


def sign_access_context(access_context: AccessContext, signing_key: str) -> str:
    return sign_encoded_access_context(encode_access_context(access_context), signing_key)


def sign_encoded_access_context(encoded: str, signing_key: str) -> str:
    key = _validated_signing_key(signing_key)
    signing_input = f"{_SIGNED_CONTEXT_PREFIX}.{encoded}"
    signature = hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return f"{signing_input}.{encoded_signature}"


def verify_signed_access_context(signed_context: str, signing_key: str) -> AccessContext:
    started = time.perf_counter()
    try:
        context = _verify_signed_access_context(signed_context, signing_key)
    except ValueError as error:
        _log_debug(
            "authguard.access_context.verify.failed",
            error_category=error_category(error),
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
        raise
    _log_debug(
        "authguard.access_context.verify.succeeded",
        principal_id=context.principal_id,
        action=context.action,
        allow_count=len(context.allow_resource_urns),
        deny_count=len(context.deny_resource_urns),
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
    return context


def _verify_signed_access_context(signed_context: str, signing_key: str) -> AccessContext:
    key = _validated_signing_key(signing_key)
    parts = signed_context.split(".")
    if len(parts) != 3 or parts[0] != _SIGNED_CONTEXT_PREFIX or not parts[1] or not parts[2]:
        raise ValueError("invalid signed Authguard access context format")
    try:
        padding = "=" * (-len(parts[2]) % 4)
        signature = base64.b64decode(parts[2] + padding, altchars=b"-_", validate=True)
    except binascii.Error as error:
        raise ValueError("invalid signed Authguard access context format") from error
    signing_input = f"{parts[0]}.{parts[1]}"
    expected = hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("invalid signed Authguard access context signature")
    return _decode_access_context(parts[1])


def _validated_signing_key(signing_key: str) -> bytes:
    key = signing_key.encode()
    if len(key) < _MIN_SIGNING_KEY_BYTES:
        raise ValueError(
            f"access context signing key must contain at least {_MIN_SIGNING_KEY_BYTES} bytes"
        )
    return key


def _string(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("expected string")
    return value


def _string_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise TypeError("expected string array")
    return tuple(value)


def _integer(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("expected integer")
    return value


def _aliased_field(payload: dict[str, Any], canonical: str, legacy: str) -> Any:
    has_canonical = canonical in payload
    has_legacy = legacy in payload
    if has_canonical and has_legacy and payload[canonical] != payload[legacy]:
        raise ValueError(f"conflicting access context fields {canonical} and {legacy}")
    if has_canonical:
        return payload[canonical]
    if has_legacy:
        return payload[legacy]
    raise KeyError(canonical)


def validate_access_context(access_context: AccessContext, now: int | None = None) -> None:
    if access_context.version != ACCESS_CONTEXT_VERSION:
        raise ValueError(f"unsupported access context version: {access_context.version}")
    now = int(time.time()) if now is None else now
    if access_context.expires_at_epoch_seconds <= access_context.issued_at_epoch_seconds:
        raise ValueError("access context expiry must be later than issue time")
    if access_context.issued_at_epoch_seconds > now + 30:
        raise ValueError("access context issue time is in the future")
    if access_context.expires_at_epoch_seconds <= now:
        raise ValueError("access context has expired")


def parse_urn_pattern(raw: str) -> UrnPattern:
    parts = raw.split(":", 6)
    if len(parts) != 7 or parts[0] != "urn" or parts[1] != "iam" or ":" in parts[6]:
        raise ValueError(f"invalid authguard urn: {raw}")
    for segment in parts[2:6]:
        if not segment or ("*" in segment and segment != "*"):
            raise ValueError(f"invalid authguard urn segment: {raw}")
    path = tuple(parts[6].split("/"))
    if not path or any(not segment for segment in path):
        raise ValueError(f"empty resource path segment: {raw}")
    for index, segment in enumerate(path):
        if segment == "**" and index != len(path) - 1:
            raise ValueError("** is only allowed as final path segment")
        if "*" in segment and segment not in {"*", "**"}:
            raise ValueError(f"partial wildcard is not supported: {segment}")
    return UrnPattern(parts[2], parts[3], parts[4], parts[5], path)


def compile_scope(mapping: ResourceSqlMapping, allow: Sequence[str], deny: Sequence[str]) -> SqlScope:
    started = time.perf_counter()
    _log_debug(
        "authguard.sql_scope.compile.started",
        allow_count=len(allow),
        deny_count=len(deny),
    )
    try:
        scope = _compile_scope(mapping, allow, deny)
    except (ValueError, TypeError) as error:
        _log_debug(
            "authguard.sql_scope.compile.failed",
            allow_count=len(allow),
            deny_count=len(deny),
            error_category=error_category(error),
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
        raise
    _log_debug(
        "authguard.sql_scope.compile.succeeded",
        allow_count=len(allow),
        deny_count=len(deny),
        scope_kind=_scope_kind(scope),
        parameter_count=len(scope.args),
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
    return scope


def _compile_scope(mapping: ResourceSqlMapping, allow: Sequence[str], deny: Sequence[str]) -> SqlScope:
    allow_scopes = [
        scope for raw in allow if (scope := _compile_pattern(mapping, parse_urn_pattern(raw))) is not None
    ]
    if not allow_scopes:
        return SqlScope("0=1")

    scope = _or(allow_scopes)
    for raw in deny:
        deny_scope = _compile_pattern(mapping, parse_urn_pattern(raw))
        if deny_scope is None:
            continue
        if deny_scope.where == "1=1":
            return SqlScope("0=1")
        scope = SqlScope(f"({scope.where}) AND NOT ({deny_scope.where})", scope.args + deny_scope.args)
    return scope


def _scope_kind(scope: SqlScope) -> str:
    if scope.where == "0=1":
        return "deny_all"
    if scope.where == "1=1":
        return "allow_all"
    return "filtered"


def current_scope(mapping: ResourceSqlMapping) -> SqlScope:
    grants = require_current()
    return compile_scope(mapping, grants.allow_resource_urns, grants.deny_resource_urns)


def current_scope_for_action(expected_action: str, mapping: ResourceSqlMapping) -> SqlScope:
    return scope_for_action(require_current_access(), expected_action, mapping)


def scope_for_action(
    request_access: RequestAccess, expected_action: str, mapping: ResourceSqlMapping
) -> SqlScope:
    if request_access.action != expected_action:
        _log_debug(
            "authguard.sql_scope.action_mismatch",
            principal_id=request_access.principal_id,
            expected_action=expected_action,
            actual_action=request_access.action,
        )
        raise PermissionError(
            f"authguard action mismatch: expected `{expected_action}`, got `{request_access.action}`"
        )
    return compile_scope(
        mapping,
        request_access.grants.allow_resource_urns,
        request_access.grants.deny_resource_urns,
    )


def _compile_pattern(mapping: ResourceSqlMapping, pattern: UrnPattern) -> SqlScope | None:
    clauses: list[str] = []
    args: list[str] = []
    if not _compile_segment(mapping.partition, pattern.partition, clauses, args):
        return None
    if not _compile_segment(mapping.service, pattern.service, clauses, args):
        return None
    if not _compile_segment(mapping.region, pattern.region, clauses, args):
        return None
    if not _compile_segment(mapping.tenant, pattern.tenant, clauses, args):
        return None
    if not _compile_path(mapping, pattern.path, clauses, args):
        return None
    return _scope(clauses, args)


def _compile_segment(mapping: SegmentMap, pattern: str, clauses: list[str], args: list[str]) -> bool:
    if pattern == "*":
        return True
    if mapping.kind == "constant":
        return mapping.value == pattern
    clauses.append(f"{mapping.value} = ?")
    args.append(pattern)
    return True


def _compile_path(
    mapping: ResourceSqlMapping,
    pattern: tuple[str, ...],
    clauses: list[str],
    args: list[str],
) -> bool:
    pidx = 0
    for path_map in mapping.path:
        if pidx < len(pattern) and pattern[pidx] == "**":
            return True
        if path_map.kind == "literal":
            if pidx >= len(pattern):
                return False
            segment = pattern[pidx]
            if segment != "*" and segment != path_map.value:
                return False
            pidx += 1
        elif path_map.kind == "column":
            if pidx >= len(pattern):
                return False
            segment = pattern[pidx]
            if segment != "*":
                clauses.append(f"{path_map.value} = ?")
                args.append(segment)
            pidx += 1
        else:
            _compile_remainder(path_map.value, pattern[pidx:], clauses, args)
            pidx = len(pattern)
    return pidx == len(pattern) or (pidx + 1 == len(pattern) and pattern[pidx] == "**")


def _compile_remainder(column: str, remaining: tuple[str, ...], clauses: list[str], args: list[str]) -> None:
    if not remaining or remaining == ("**",):
        return
    if "*" in remaining:
        raise ValueError("wildcard inside a remainder column is not SQL-pushdown safe")
    if remaining[-1] == "**":
        prefix = "/".join(remaining[:-1])
        if prefix:
            clauses.append(f"({column} = ? OR {column} LIKE ?)")
            args.append(prefix)
            args.append(f"{prefix}/%")
        return
    clauses.append(f"{column} = ?")
    args.append("/".join(remaining))


def _scope(clauses: list[str], args: list[str]) -> SqlScope:
    if not clauses:
        return SqlScope("1=1", tuple(args))
    return SqlScope(" AND ".join(clauses), tuple(args))


def _or(scopes: list[SqlScope]) -> SqlScope:
    if len(scopes) == 1:
        return scopes[0]
    if any(scope.where == "1=1" for scope in scopes):
        return SqlScope("1=1")
    return SqlScope(" OR ".join(f"({scope.where})" for scope in scopes), tuple(arg for scope in scopes for arg in scope.args))
