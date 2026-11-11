from __future__ import annotations

from app.dto.customer_growth_job_dto import (
    CustomerGrowthJobDTO,
    CustomerGrowthJobSearchRequest,
    CreateCustomerGrowthJobRequest,
    UpdateCustomerGrowthJobRequest,
)
from app.service.customer_growth_job_service import CustomerGrowthJobService


class CustomerGrowthJobController:
    def __init__(self, service: CustomerGrowthJobService) -> None:
        self._service = service

    def create_job(self, request: CreateCustomerGrowthJobRequest) -> CustomerGrowthJobDTO:
        return self._service.create_job(request)

    def get_job(self, job_id: int) -> CustomerGrowthJobDTO | None:
        return self._service.get_job(job_id)

    def update_job(self, job_id: int, request: UpdateCustomerGrowthJobRequest) -> CustomerGrowthJobDTO:
        return self._service.update_job(job_id, request)

    def delete_job(self, job_id: int) -> None:
        self._service.delete_job(job_id)

    def list_visible_jobs(
        self,
        request: CustomerGrowthJobSearchRequest,
    ) -> list[CustomerGrowthJobDTO]:
        return self._service.list_visible_jobs(request)
