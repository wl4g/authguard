package authorization

import "authguard/adapters/golang/model"

const (
	ActionCreate = "customer-growth.job.create"
	ActionRead   = "customer-growth.job.read"
	ActionUpdate = "customer-growth.job.update"
	ActionDelete = "customer-growth.job.delete"
)

func CustomerGrowthJobResourceMapping() model.ResourceSQLMapping {
	return model.ResourceSQLMapping{
		Partition: model.ConstSegment("prod"),
		Service:   model.ConstSegment("customer-growth"),
		Region:    model.ColumnSegment("region"),
		Tenant:    model.ColumnSegment("tenant_id"),
		Path: []model.PathMap{
			model.LiteralPath("workspace"),
			model.ColumnPath("workspace_id"),
			model.LiteralPath("project"),
			model.ColumnPath("project_id"),
			model.LiteralPath("job"),
			model.ColumnPath("job_id"),
		},
	}
}
