package entity

type CustomerGrowthJobEntity struct {
	ID          int64  `db:"id"`
	Region      string `db:"region"`
	TenantID    string `db:"tenant_id"`
	WorkspaceID string `db:"workspace_id"`
	ProjectID   string `db:"project_id"`
	JobID       string `db:"job_id"`
	DisplayName string `db:"display_name"`
	Status      string `db:"status"`
	OwnerUserID string `db:"owner_user_id"`
}

type CustomerGrowthJobQueryCriteria struct {
	WorkspaceID string
	ProjectID   string
	Status      string
	OwnerUserID string
}
