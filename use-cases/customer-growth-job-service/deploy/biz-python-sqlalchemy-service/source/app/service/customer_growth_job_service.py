from __future__ import annotations

from app.authorization import ACTION_CREATE, ACTION_DELETE, ACTION_READ, ACTION_UPDATE, customer_growth_job_mapping
from app.dto.customer_growth_job_dto import (
    CustomerGrowthJobDTO,
    CustomerGrowthJobSearchRequest,
    CreateCustomerGrowthJobRequest,
    UpdateCustomerGrowthJobRequest,
)
from app.entity.customer_growth_job_entity import CustomerGrowthJobEntity, CustomerGrowthJobQueryCriteria
from app.repository.customer_growth_job_repository import CustomerGrowthJobRepository
from authguard_adapter.model import SqlScope
from authguard_adapter.util import current_scope_for_action


class CustomerGrowthJobService:
    def __init__(self, repository: CustomerGrowthJobRepository) -> None:
        self._repository = repository

    def create_job(self, request: CreateCustomerGrowthJobRequest) -> CustomerGrowthJobDTO:
        scope = _scope_for_action(ACTION_CREATE)
        job = _to_entity(request)
        if not self._repository.is_candidate_visible(scope, job):
            raise LookupError(f"customer growth job not found or not authorized: {job.id}")
        return _to_dto(self._repository.create(job))

    def get_job(self, job_id: int) -> CustomerGrowthJobDTO | None:
        job = self._repository.find_by_id_visible(_scope_for_action(ACTION_READ), job_id)
        return _to_dto(job) if job is not None else None

    def update_job(self, job_id: int, request: UpdateCustomerGrowthJobRequest) -> CustomerGrowthJobDTO:
        scope = _scope_for_action(ACTION_UPDATE)
        job = self._repository.find_by_id_visible(scope, job_id)
        if job is None:
            raise LookupError(f"customer growth job not found: {job_id}")
        updated = CustomerGrowthJobEntity(
            id=job.id,
            region=job.region,
            tenant_id=job.tenant_id,
            workspace_id=job.workspace_id,
            project_id=job.project_id,
            job_id=job.job_id,
            display_name=request.display_name,
            status=request.status,
            owner_user_id=request.owner_user_id,
        )
        return _to_dto(self._repository.update_visible(scope, updated))

    def delete_job(self, job_id: int) -> None:
        self._repository.delete_by_id_visible(_scope_for_action(ACTION_DELETE), job_id)

    def list_visible_jobs(
        self,
        request: CustomerGrowthJobSearchRequest,
    ) -> list[CustomerGrowthJobDTO]:
        scope = _scope_for_action(ACTION_READ)
        criteria = CustomerGrowthJobQueryCriteria(
            workspace_id=request.workspace_id,
            project_id=request.project_id,
            status=request.status,
            owner_user_id=request.owner_user_id,
        )
        return [_to_dto(job) for job in self._repository.find_visible_jobs(scope, criteria)]


def _scope_for_action(action: str) -> SqlScope:
    return current_scope_for_action(action, customer_growth_job_mapping())


def _to_entity(request: CreateCustomerGrowthJobRequest) -> CustomerGrowthJobEntity:
    return CustomerGrowthJobEntity(
        id=request.id,
        region=request.region,
        tenant_id=request.tenant_id,
        workspace_id=request.workspace_id,
        project_id=request.project_id,
        job_id=request.job_id,
        display_name=request.display_name,
        status=request.status,
        owner_user_id=request.owner_user_id,
    )


def _to_dto(job: CustomerGrowthJobEntity) -> CustomerGrowthJobDTO:
    return CustomerGrowthJobDTO(
        id=job.id,
        region=job.region,
        tenant_id=job.tenant_id,
        workspace_id=job.workspace_id,
        project_id=job.project_id,
        job_id=job.job_id,
        display_name=job.display_name,
        status=job.status,
        owner_user_id=job.owner_user_id,
    )
