from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Literal, Sequence

ACCESS_CONTEXT_VERSION = 3


@dataclass(frozen=True)
class SqlScope:
    where: str
    args: tuple[str, ...] = ()


@dataclass(frozen=True)
class AccessGrantSet:
    allow_resource_urns: tuple[str, ...] = ()
    deny_resource_urns: tuple[str, ...] = ()


@dataclass(frozen=True)
class RequestAccess:
    principal_id: str
    action: str
    resource_urn: str
    grants: AccessGrantSet

    @staticmethod
    def from_grants(grants: AccessGrantSet) -> RequestAccess:
        return RequestAccess("", "", "", grants)


@dataclass(frozen=True)
class AccessContext:
    version: int
    principal_id: str
    action: str
    resource_urn: str
    allow_resource_urns: tuple[str, ...] = ()
    deny_resource_urns: tuple[str, ...] = ()
    policy_revision: int = 0
    issued_at_epoch_seconds: int = 0
    expires_at_epoch_seconds: int = 0

    @staticmethod
    def active(
        principal_id: str,
        action: str,
        resource_urn: str,
        allow_resource_urns: tuple[str, ...] = (),
        deny_resource_urns: tuple[str, ...] = (),
        *,
        policy_revision: int = 1,
        ttl_seconds: int = 30,
    ) -> AccessContext:
        now = int(time.time())
        return AccessContext(
            ACCESS_CONTEXT_VERSION,
            principal_id,
            action,
            resource_urn,
            allow_resource_urns,
            deny_resource_urns,
            policy_revision,
            now,
            now + ttl_seconds,
        )

    def grant_set(self) -> AccessGrantSet:
        return AccessGrantSet(self.allow_resource_urns, self.deny_resource_urns)

    def request_access(self) -> RequestAccess:
        return RequestAccess(self.principal_id, self.action, self.resource_urn, self.grant_set())


@dataclass(frozen=True)
class UrnPattern:
    partition: str
    service: str
    region: str
    tenant: str
    path: tuple[str, ...]


@dataclass(frozen=True)
class SegmentMap:
    kind: Literal["constant", "column"]
    value: str

    @staticmethod
    def constant(value: str) -> SegmentMap:
        return SegmentMap("constant", value)

    @staticmethod
    def column(name: str) -> SegmentMap:
        return SegmentMap("column", name)


@dataclass(frozen=True)
class PathMap:
    kind: Literal["literal", "column", "remainder_column"]
    value: str

    @staticmethod
    def literal(value: str) -> PathMap:
        return PathMap("literal", value)

    @staticmethod
    def column(name: str) -> PathMap:
        return PathMap("column", name)

    @staticmethod
    def remainder_column(name: str) -> PathMap:
        return PathMap("remainder_column", name)


@dataclass(frozen=True)
class ResourceSqlMapping:
    partition: SegmentMap
    service: SegmentMap
    region: SegmentMap
    tenant: SegmentMap
    path: tuple[PathMap, ...]

    def compile_scope(self, allow: Sequence[str], deny: Sequence[str]) -> SqlScope:
        from authguard_adapter.util import compile_scope

        return compile_scope(self, allow, deny)
