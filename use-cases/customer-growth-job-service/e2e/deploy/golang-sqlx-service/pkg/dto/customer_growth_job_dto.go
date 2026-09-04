package dto

type CustomerGrowthJobSearchRequest struct {
	WorkspaceID string `json:"workspace_id"`
	ProjectID   string `json:"project_id"`
	Status      string `json:"status"`
	OwnerUserID string `json:"owner_user_id"`
}

type CreateCustomerGrowthJobRequest struct {
	ID          int64  `json:"id"`
	Region      string `json:"region"`
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	ProjectID   string `json:"project_id"`
	JobID       string `json:"job_id"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	OwnerUserID string `json:"owner_user_id"`
}

type UpdateCustomerGrowthJobRequest struct {
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	OwnerUserID string `json:"owner_user_id"`
}

type CustomerGrowthJobDTO struct {
	ID          int64  `json:"id"`
	Region      string `json:"region"`
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	ProjectID   string `json:"project_id"`
	JobID       string `json:"job_id"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	OwnerUserID string `json:"owner_user_id"`
}
