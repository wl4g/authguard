use crate::{
    customer_growth_job_authorization::{
        customer_growth_job_mapping, ACTION_CREATE, ACTION_DELETE, ACTION_READ, ACTION_UPDATE,
    },
    customer_growth_job_dto::{
        CreateCustomerGrowthJobRequest, CustomerGrowthJobDto, CustomerGrowthJobSearchRequest,
        UpdateCustomerGrowthJobRequest,
    },
    customer_growth_job_entity::{CustomerGrowthJobEntity, CustomerGrowthJobQueryCriteria},
    customer_growth_job_repository::CustomerGrowthJobRepository,
};
use authguard_adapter_rust::{util, RequestAccess};

#[derive(Debug, Clone)]
pub struct CustomerGrowthJobService {
    repository: CustomerGrowthJobRepository,
}

impl CustomerGrowthJobService {
    #[must_use]
    pub fn new(repository: CustomerGrowthJobRepository) -> Self {
        Self { repository }
    }

    /// Creates a customer growth job and returns the persisted DTO.
    ///
    /// # Errors
    ///
    /// Returns an error when repository persistence fails.
    pub async fn create_job(
        &self,
        access: &RequestAccess,
        request: CreateCustomerGrowthJobRequest,
    ) -> anyhow::Result<CustomerGrowthJobDto> {
        let scope = scope_for_action(access, ACTION_CREATE)?;
        let job = to_entity(request);
        if !self.repository.is_candidate_visible(&scope, &job).await? {
            anyhow::bail!("customer growth job not found or not authorized: {}", job.id);
        }
        Ok(to_dto(self.repository.create(job).await?))
    }

    /// Loads one customer growth job by id.
    ///
    /// # Errors
    ///
    /// Returns an error when repository access fails.
    pub async fn get_job(
        &self,
        access: &RequestAccess,
        id: i64,
    ) -> anyhow::Result<Option<CustomerGrowthJobDto>> {
        let scope = scope_for_action(access, ACTION_READ)?;
        Ok(self.repository.find_by_id_visible(&scope, id).await?.map(to_dto))
    }

    /// Updates mutable customer growth job metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the job is missing or repository persistence fails.
    pub async fn update_job(
        &self,
        access: &RequestAccess,
        id: i64,
        request: UpdateCustomerGrowthJobRequest,
    ) -> anyhow::Result<CustomerGrowthJobDto> {
        let scope = scope_for_action(access, ACTION_UPDATE)?;
        let mut job = self
            .repository
            .find_by_id_visible(&scope, id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("customer growth job not found: {id}"))?;
        job.display_name = request.display_name;
        job.status = request.status;
        job.owner_user_id = request.owner_user_id;
        Ok(to_dto(self.repository.update_visible(&scope, job).await?))
    }

    /// Deletes a customer growth job by id.
    ///
    /// # Errors
    ///
    /// Returns an error when repository persistence fails.
    pub async fn delete_job(&self, access: &RequestAccess, id: i64) -> anyhow::Result<()> {
        let scope = scope_for_action(access, ACTION_DELETE)?;
        self.repository.delete_by_id_visible(&scope, id).await
    }

    /// Compiles the user's Authguard Resource URNs into a SQL scope and queries
    /// the business repository.
    ///
    /// # Errors
    ///
    /// Returns an error when Authguard scope compilation or SQL execution fails.
    pub async fn list_visible_jobs(
        &self,
        access: &RequestAccess,
        request: &CustomerGrowthJobSearchRequest,
    ) -> anyhow::Result<Vec<CustomerGrowthJobDto>> {
        let scope = scope_for_action(access, ACTION_READ)?;
        let criteria = CustomerGrowthJobQueryCriteria {
            workspace_id: request.workspace_id.clone(),
            project_id: request.project_id.clone(),
            status: request.status.clone(),
            owner_user_id: request.owner_user_id.clone(),
        };
        let jobs = self.repository.find_visible_jobs(&scope, &criteria).await?;
        Ok(to_dtos(jobs))
    }
}

fn scope_for_action(
    access: &RequestAccess,
    action: &str,
) -> anyhow::Result<authguard_adapter_rust::model::SqlScope> {
    let mapping = customer_growth_job_mapping();
    Ok(util::scope_for_action(access, action, &mapping)?)
}

fn to_entity(request: CreateCustomerGrowthJobRequest) -> CustomerGrowthJobEntity {
    CustomerGrowthJobEntity {
        id: request.id,
        region: request.region,
        tenant_id: request.tenant_id,
        workspace_id: request.workspace_id,
        project_id: request.project_id,
        job_id: request.job_id,
        display_name: request.display_name,
        status: request.status,
        owner_user_id: request.owner_user_id,
    }
}

fn to_dtos(entities: Vec<CustomerGrowthJobEntity>) -> Vec<CustomerGrowthJobDto> {
    entities.into_iter().map(to_dto).collect()
}

fn to_dto(job: CustomerGrowthJobEntity) -> CustomerGrowthJobDto {
    CustomerGrowthJobDto {
        id: job.id,
        region: job.region,
        tenant_id: job.tenant_id,
        workspace_id: job.workspace_id,
        project_id: job.project_id,
        job_id: job.job_id,
        display_name: job.display_name,
        status: job.status,
        owner_user_id: job.owner_user_id,
    }
}
