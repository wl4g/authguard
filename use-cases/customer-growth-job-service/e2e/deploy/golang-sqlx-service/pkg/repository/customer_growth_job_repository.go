package repository

import (
	"database/sql"
	"errors"
	"strings"

	"authguard/adapters/golang/model"
	"authguard/use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service/pkg/entity"

	"github.com/jmoiron/sqlx"
)

var ErrCustomerGrowthJobNotFound = errors.New("customer growth job not found")

type CustomerGrowthJobRepository struct {
	db *sqlx.DB
}

func NewCustomerGrowthJobRepository(db *sqlx.DB) *CustomerGrowthJobRepository {
	return &CustomerGrowthJobRepository{db: db}
}

func (r *CustomerGrowthJobRepository) Create(job entity.CustomerGrowthJobEntity) (entity.CustomerGrowthJobEntity, error) {
	query := r.db.Rebind("INSERT INTO customer_growth_jobs(id, region, tenant_id, workspace_id, project_id, job_id, display_name, status, owner_user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
	_, err := r.db.Exec(
		query,
		job.ID, job.Region, job.TenantID, job.WorkspaceID, job.ProjectID, job.JobID, job.DisplayName, job.Status, job.OwnerUserID,
	)
	return job, err
}

func (r *CustomerGrowthJobRepository) FindByIDVisible(scope model.SqlScope, id int64) (entity.CustomerGrowthJobEntity, bool, error) {
	var job entity.CustomerGrowthJobEntity
	args := append([]any{id}, scope.Args...)
	query := r.db.Rebind("SELECT * FROM customer_growth_jobs WHERE id = ? AND (" + scope.Where + ")")
	err := r.db.Get(&job, query, args...)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return entity.CustomerGrowthJobEntity{}, false, nil
		}
		return entity.CustomerGrowthJobEntity{}, false, err
	}
	return job, true, nil
}

func (r *CustomerGrowthJobRepository) UpdateVisible(scope model.SqlScope, job entity.CustomerGrowthJobEntity) (entity.CustomerGrowthJobEntity, error) {
	args := []any{job.DisplayName, job.Status, job.OwnerUserID, job.ID}
	args = append(args, scope.Args...)
	query := r.db.Rebind("UPDATE customer_growth_jobs SET display_name = ?, status = ?, owner_user_id = ? WHERE id = ? AND (" + scope.Where + ")")
	result, err := r.db.Exec(
		query,
		args...,
	)
	if err != nil {
		return entity.CustomerGrowthJobEntity{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return entity.CustomerGrowthJobEntity{}, err
	}
	if affected == 0 {
		return entity.CustomerGrowthJobEntity{}, ErrCustomerGrowthJobNotFound
	}
	return job, nil
}

func (r *CustomerGrowthJobRepository) DeleteByIDVisible(scope model.SqlScope, id int64) error {
	args := append([]any{id}, scope.Args...)
	query := r.db.Rebind("DELETE FROM customer_growth_jobs WHERE id = ? AND (" + scope.Where + ")")
	result, err := r.db.Exec(query, args...)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrCustomerGrowthJobNotFound
	}
	return nil
}

func (r *CustomerGrowthJobRepository) IsCandidateVisible(scope model.SqlScope, job entity.CustomerGrowthJobEntity) (bool, error) {
	args := []any{job.Region, job.TenantID, job.WorkspaceID, job.ProjectID, job.JobID}
	args = append(args, scope.Args...)
	var visible int
	query := r.db.Rebind(
		"SELECT COUNT(*) FROM (SELECT CAST(? AS VARCHAR(32)) AS region, CAST(? AS VARCHAR(128)) AS tenant_id, CAST(? AS VARCHAR(128)) AS workspace_id, CAST(? AS VARCHAR(128)) AS project_id, CAST(? AS VARCHAR(128)) AS job_id) candidate WHERE " + scope.Where,
	)
	err := r.db.Get(
		&visible,
		query,
		args...,
	)
	return visible == 1, err
}

func (r *CustomerGrowthJobRepository) FindVisibleJobs(scope model.SqlScope, criteria entity.CustomerGrowthJobQueryCriteria) ([]entity.CustomerGrowthJobEntity, error) {
	var jobs []entity.CustomerGrowthJobEntity
	clauses := []string{scope.Where}
	args := append([]any{}, scope.Args...)
	addEquals(&clauses, &args, "workspace_id", criteria.WorkspaceID)
	addEquals(&clauses, &args, "project_id", criteria.ProjectID)
	addEquals(&clauses, &args, "status", criteria.Status)
	addEquals(&clauses, &args, "owner_user_id", criteria.OwnerUserID)
	query := r.db.Rebind("SELECT * FROM customer_growth_jobs WHERE " + strings.Join(clauses, " AND ") +
		" ORDER BY region, tenant_id, workspace_id, project_id, job_id",
	)
	err := r.db.Select(
		&jobs,
		query,
		args...,
	)
	return jobs, err
}

func addEquals(clauses *[]string, args *[]any, column string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	*clauses = append(*clauses, column+" = ?")
	*args = append(*args, value)
}
