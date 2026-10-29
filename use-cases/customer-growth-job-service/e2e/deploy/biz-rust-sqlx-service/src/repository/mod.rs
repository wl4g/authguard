use std::fmt::Write;

use authguard_adapter_rust::model::SqlScope;
use sqlx::{any::AnyRow, Any, AnyPool, Row};

use crate::entity::{CustomerGrowthJobEntity, CustomerGrowthJobQueryCriteria};

#[derive(Debug, Clone)]
pub struct CustomerGrowthJobRepository {
    pool: AnyPool,
}

impl CustomerGrowthJobRepository {
    #[must_use]
    pub fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    /// Inserts one customer growth job.
    ///
    /// # Errors
    ///
    /// Returns an error when SQL execution fails.
    pub async fn create(
        &self,
        job: CustomerGrowthJobEntity,
    ) -> anyhow::Result<CustomerGrowthJobEntity> {
        sqlx::query(&bind_sql(
            "INSERT INTO e2e_authguard_customer_growth_jobs(id, region, tenant_id, workspace_id, project_id, job_id, display_name, status, owner_user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ))
        .bind(job.id)
        .bind(&job.region)
        .bind(&job.tenant_id)
        .bind(&job.workspace_id)
        .bind(&job.project_id)
        .bind(&job.job_id)
        .bind(&job.display_name)
        .bind(&job.status)
        .bind(&job.owner_user_id)
        .execute(&self.pool)
        .await?;
        Ok(job)
    }

    /// Finds one customer growth job by id within the authorized row scope.
    ///
    /// # Errors
    ///
    /// Returns an error when SQL execution fails.
    pub async fn find_by_id_visible(
        &self,
        scope: &SqlScope,
        id: i64,
    ) -> anyhow::Result<Option<CustomerGrowthJobEntity>> {
        let sql = bind_sql(&format!(
            "SELECT * FROM e2e_authguard_customer_growth_jobs WHERE id = ? AND ({})",
            scope.where_clause
        ));
        let mut query = sqlx::query(&sql).bind(id);
        for param in &scope.params {
            query = query.bind(param);
        }
        Ok(query.fetch_optional(&self.pool).await?.map(|row| row_to_entity(&row)))
    }

    /// Updates mutable metadata only when the target row remains in scope.
    ///
    /// # Errors
    ///
    /// Returns an error when SQL execution fails or the job is invisible.
    pub async fn update_visible(
        &self,
        scope: &SqlScope,
        job: CustomerGrowthJobEntity,
    ) -> anyhow::Result<CustomerGrowthJobEntity> {
        let sql = bind_sql(&format!(
            "UPDATE e2e_authguard_customer_growth_jobs SET display_name = ?, status = ?, owner_user_id = ? WHERE id = ? AND ({})",
            scope.where_clause
        ));
        let mut query = sqlx::query(&sql)
            .bind(&job.display_name)
            .bind(&job.status)
            .bind(&job.owner_user_id)
            .bind(job.id);
        for param in &scope.params {
            query = query.bind(param);
        }
        if query.execute(&self.pool).await?.rows_affected() == 0 {
            anyhow::bail!("customer growth job not found or not authorized: {}", job.id);
        }
        Ok(job)
    }

    /// Deletes one row only when it remains in the authorized scope.
    ///
    /// # Errors
    ///
    /// Returns an error when SQL execution fails or the job is invisible.
    pub async fn delete_by_id_visible(&self, scope: &SqlScope, id: i64) -> anyhow::Result<()> {
        let sql = bind_sql(&format!(
            "DELETE FROM e2e_authguard_customer_growth_jobs WHERE id = ? AND ({})",
            scope.where_clause
        ));
        let mut query = sqlx::query(&sql).bind(id);
        for param in &scope.params {
            query = query.bind(param);
        }
        if query.execute(&self.pool).await?.rows_affected() == 0 {
            anyhow::bail!("customer growth job not found or not authorized: {id}");
        }
        Ok(())
    }

    /// Checks a not-yet-persisted resource against the compiled row scope.
    ///
    /// # Errors
    ///
    /// Returns an error when candidate-scope SQL execution fails.
    pub async fn is_candidate_visible(
        &self,
        scope: &SqlScope,
        job: &CustomerGrowthJobEntity,
    ) -> anyhow::Result<bool> {
        let sql = bind_sql(&format!(
            "SELECT COUNT(*) FROM (SELECT CAST(? AS VARCHAR(32)) AS region, CAST(? AS VARCHAR(128)) AS tenant_id, CAST(? AS VARCHAR(128)) AS workspace_id, CAST(? AS VARCHAR(128)) AS project_id, CAST(? AS VARCHAR(128)) AS job_id) candidate WHERE {}",
            scope.where_clause
        ));
        let mut query = sqlx::query_scalar::<Any, i64>(&sql)
            .bind(&job.region)
            .bind(&job.tenant_id)
            .bind(&job.workspace_id)
            .bind(&job.project_id)
            .bind(&job.job_id);
        for param in &scope.params {
            query = query.bind(param);
        }
        Ok(query.fetch_one(&self.pool).await? == 1)
    }

    /// Applies an Authguard SQL scope and business search criteria.
    ///
    /// # Errors
    ///
    /// Returns an error when SQL execution fails.
    pub async fn find_visible_jobs(
        &self,
        scope: &SqlScope,
        criteria: &CustomerGrowthJobQueryCriteria,
    ) -> anyhow::Result<Vec<CustomerGrowthJobEntity>> {
        let mut clauses = vec![scope.where_clause.clone()];
        let mut params = scope.params.clone();
        add_equals(&mut clauses, &mut params, "workspace_id", criteria.workspace_id.as_deref());
        add_equals(&mut clauses, &mut params, "project_id", criteria.project_id.as_deref());
        add_equals(&mut clauses, &mut params, "status", criteria.status.as_deref());
        add_equals(&mut clauses, &mut params, "owner_user_id", criteria.owner_user_id.as_deref());
        let sql = bind_sql(&format!(
            "SELECT * FROM e2e_authguard_customer_growth_jobs WHERE {} ORDER BY region, tenant_id, workspace_id, project_id, job_id",
            clauses.join(" AND ")
        ));
        let mut query = sqlx::query(&sql);
        for param in &params {
            query = query.bind(param);
        }
        Ok(query.map(|row| row_to_entity(&row)).fetch_all(&self.pool).await?)
    }

    /// Verifies that the backing database is reachable.
    ///
    /// # Errors
    ///
    /// Returns an error when the health query fails.
    pub async fn ping(&self) -> anyhow::Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }
}

fn add_equals(
    clauses: &mut Vec<String>,
    params: &mut Vec<String>,
    column: &str,
    value: Option<&str>,
) {
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return;
    };
    clauses.push(format!("{column} = ?"));
    params.push(value.to_string());
}

fn bind_sql(sql: &str) -> String {
    let mut index = 0;
    sql.chars().fold(String::with_capacity(sql.len()), |mut bound, character| {
        if character == '?' {
            index += 1;
            let _ = write!(bound, "${index}");
        } else {
            bound.push(character);
        }
        bound
    })
}

fn row_to_entity(row: &AnyRow) -> CustomerGrowthJobEntity {
    CustomerGrowthJobEntity {
        id: row.get("id"),
        region: row.get("region"),
        tenant_id: row.get("tenant_id"),
        workspace_id: row.get("workspace_id"),
        project_id: row.get("project_id"),
        job_id: row.get("job_id"),
        display_name: row.get("display_name"),
        status: row.get("status"),
        owner_user_id: row.get("owner_user_id"),
    }
}
