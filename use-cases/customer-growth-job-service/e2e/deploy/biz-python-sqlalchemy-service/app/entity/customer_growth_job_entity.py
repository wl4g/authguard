from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CustomerGrowthJobEntity:
    id: int
    region: str
    tenant_id: str
    workspace_id: str
    project_id: str
    job_id: str
    display_name: str
    status: str
    owner_user_id: str


@dataclass(frozen=True)
class CustomerGrowthJobQueryCriteria:
    workspace_id: str | None = None
    project_id: str | None = None
    status: str | None = None
    owner_user_id: str | None = None
