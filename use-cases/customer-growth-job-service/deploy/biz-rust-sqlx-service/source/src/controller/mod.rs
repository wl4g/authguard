use crate::{
    dto::{
        CreateCustomerGrowthJobRequest, CustomerGrowthJobDto, CustomerGrowthJobSearchRequest,
        UpdateCustomerGrowthJobRequest,
    },
    service::CustomerGrowthJobService,
};
use authguard_adapter_rust::RequestAccess;

pub mod http;

#[derive(Debug, Clone)]
pub struct CustomerGrowthJobController {
    service: CustomerGrowthJobService,
}

impl CustomerGrowthJobController {
    #[must_use]
    pub fn new(service: CustomerGrowthJobService) -> Self {
        Self { service }
    }

    /// Creates a customer growth job.
    ///
    /// # Errors
    ///
    /// Returns an error when repository persistence fails.
    pub async fn create_job(
        &self,
        access: &RequestAccess,
        request: CreateCustomerGrowthJobRequest,
    ) -> anyhow::Result<CustomerGrowthJobDto> {
        self.service.create_job(access, request).await
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
        self.service.get_job(access, id).await
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
        self.service.update_job(access, id, request).await
    }

    /// Deletes an customer growth job by id.
    ///
    /// # Errors
    ///
    /// Returns an error when repository persistence fails.
    pub async fn delete_job(&self, access: &RequestAccess, id: i64) -> anyhow::Result<()> {
        self.service.delete_job(access, id).await
    }

    /// Lists customer growth jobs visible to the current user.
    ///
    /// # Errors
    ///
    /// Returns an error when Authguard scope compilation or SQL execution fails.
    pub async fn list_visible_jobs(
        &self,
        access: &RequestAccess,
        request: &CustomerGrowthJobSearchRequest,
    ) -> anyhow::Result<Vec<CustomerGrowthJobDto>> {
        self.service.list_visible_jobs(access, request).await
    }
}
