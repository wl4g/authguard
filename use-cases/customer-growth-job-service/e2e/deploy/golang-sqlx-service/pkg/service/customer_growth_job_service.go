package service

import (
	"context"

	"authguard/adapters/golang/access"
	"authguard/adapters/golang/model"
	"authguard/use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service/pkg/authorization"
	"authguard/use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service/pkg/dto"
	"authguard/use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service/pkg/entity"
	"authguard/use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service/pkg/repository"
)

type CustomerGrowthJobService struct {
	repository *repository.CustomerGrowthJobRepository
}

func NewCustomerGrowthJobService(repository *repository.CustomerGrowthJobRepository) *CustomerGrowthJobService {
	return &CustomerGrowthJobService{repository: repository}
}

func (s *CustomerGrowthJobService) CreateJob(ctx context.Context, request dto.CreateCustomerGrowthJobRequest) (dto.CustomerGrowthJobDTO, error) {
	scope, err := scopeForAction(ctx, authorization.ActionCreate)
	if err != nil {
		return dto.CustomerGrowthJobDTO{}, err
	}
	entity := toEntity(request)
	visible, err := s.repository.IsCandidateVisible(scope, entity)
	if err != nil {
		return dto.CustomerGrowthJobDTO{}, err
	}
	if !visible {
		return dto.CustomerGrowthJobDTO{}, repository.ErrCustomerGrowthJobNotFound
	}
	job, err := s.repository.Create(entity)
	if err != nil {
		return dto.CustomerGrowthJobDTO{}, err
	}
	return toDTO(job), nil
}

func (s *CustomerGrowthJobService) GetJob(ctx context.Context, id int64) (dto.CustomerGrowthJobDTO, bool, error) {
	scope, err := scopeForAction(ctx, authorization.ActionRead)
	if err != nil {
		return dto.CustomerGrowthJobDTO{}, false, err
	}
	job, ok, err := s.repository.FindByIDVisible(scope, id)
	if err != nil || !ok {
		return dto.CustomerGrowthJobDTO{}, ok, err
	}
	return toDTO(job), true, nil
}

func (s *CustomerGrowthJobService) UpdateJob(ctx context.Context, id int64, request dto.UpdateCustomerGrowthJobRequest) (dto.CustomerGrowthJobDTO, error) {
	scope, err := scopeForAction(ctx, authorization.ActionUpdate)
	if err != nil {
		return dto.CustomerGrowthJobDTO{}, err
	}
	job, ok, err := s.repository.FindByIDVisible(scope, id)
	if err != nil {
		return dto.CustomerGrowthJobDTO{}, err
	}
	if !ok {
		return dto.CustomerGrowthJobDTO{}, repository.ErrCustomerGrowthJobNotFound
	}
	job.DisplayName = request.DisplayName
	job.Status = request.Status
	job.OwnerUserID = request.OwnerUserID
	updated, err := s.repository.UpdateVisible(scope, job)
	if err != nil {
		return dto.CustomerGrowthJobDTO{}, err
	}
	return toDTO(updated), nil
}

func (s *CustomerGrowthJobService) DeleteJob(ctx context.Context, id int64) error {
	scope, err := scopeForAction(ctx, authorization.ActionDelete)
	if err != nil {
		return err
	}
	return s.repository.DeleteByIDVisible(scope, id)
}

func (s *CustomerGrowthJobService) ListVisibleJobs(ctx context.Context, request dto.CustomerGrowthJobSearchRequest) ([]dto.CustomerGrowthJobDTO, error) {
	scope, err := scopeForAction(ctx, authorization.ActionRead)
	if err != nil {
		return nil, err
	}
	criteria := entity.CustomerGrowthJobQueryCriteria{
		WorkspaceID: request.WorkspaceID,
		ProjectID:   request.ProjectID,
		Status:      request.Status,
		OwnerUserID: request.OwnerUserID,
	}
	entities, err := s.repository.FindVisibleJobs(scope, criteria)
	if err != nil {
		return nil, err
	}
	return toDTOs(entities), nil
}

func scopeForAction(ctx context.Context, action string) (model.SqlScope, error) {
	return access.CurrentScopeForAction(ctx, action, authorization.CustomerGrowthJobResourceMapping())
}

func toEntity(request dto.CreateCustomerGrowthJobRequest) entity.CustomerGrowthJobEntity {
	return entity.CustomerGrowthJobEntity{
		ID:          request.ID,
		Region:      request.Region,
		TenantID:    request.TenantID,
		WorkspaceID: request.WorkspaceID,
		ProjectID:   request.ProjectID,
		JobID:       request.JobID,
		DisplayName: request.DisplayName,
		Status:      request.Status,
		OwnerUserID: request.OwnerUserID,
	}
}

func toDTOs(entities []entity.CustomerGrowthJobEntity) []dto.CustomerGrowthJobDTO {
	jobs := make([]dto.CustomerGrowthJobDTO, 0, len(entities))
	for _, job := range entities {
		jobs = append(jobs, toDTO(job))
	}
	return jobs
}

func toDTO(job entity.CustomerGrowthJobEntity) dto.CustomerGrowthJobDTO {
	return dto.CustomerGrowthJobDTO{
		ID:          job.ID,
		Region:      job.Region,
		TenantID:    job.TenantID,
		WorkspaceID: job.WorkspaceID,
		ProjectID:   job.ProjectID,
		JobID:       job.JobID,
		DisplayName: job.DisplayName,
		Status:      job.Status,
		OwnerUserID: job.OwnerUserID,
	}
}
