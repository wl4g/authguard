package controller

import (
	"context"

	"authguard/use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service/pkg/dto"
	"authguard/use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service/pkg/service"
)

type CustomerGrowthJobController struct {
	service *service.CustomerGrowthJobService
}

func NewCustomerGrowthJobController(service *service.CustomerGrowthJobService) *CustomerGrowthJobController {
	return &CustomerGrowthJobController{service: service}
}

func (c *CustomerGrowthJobController) CreateJob(ctx context.Context, request dto.CreateCustomerGrowthJobRequest) (dto.CustomerGrowthJobDTO, error) {
	return c.service.CreateJob(ctx, request)
}

func (c *CustomerGrowthJobController) GetJob(ctx context.Context, id int64) (dto.CustomerGrowthJobDTO, bool, error) {
	return c.service.GetJob(ctx, id)
}

func (c *CustomerGrowthJobController) UpdateJob(ctx context.Context, id int64, request dto.UpdateCustomerGrowthJobRequest) (dto.CustomerGrowthJobDTO, error) {
	return c.service.UpdateJob(ctx, id, request)
}

func (c *CustomerGrowthJobController) DeleteJob(ctx context.Context, id int64) error {
	return c.service.DeleteJob(ctx, id)
}

func (c *CustomerGrowthJobController) ListVisibleJobs(ctx context.Context, request dto.CustomerGrowthJobSearchRequest) ([]dto.CustomerGrowthJobDTO, error) {
	return c.service.ListVisibleJobs(ctx, request)
}
