use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct CustomerGrowthJobSearchRequest {
    pub workspace_id: Option<String>,
    pub project_id: Option<String>,
    pub status: Option<String>,
    pub owner_user_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CreateCustomerGrowthJobRequest {
    pub id: i64,
    pub region: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub project_id: String,
    pub job_id: String,
    pub display_name: String,
    pub status: String,
    pub owner_user_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UpdateCustomerGrowthJobRequest {
    pub display_name: String,
    pub status: String,
    pub owner_user_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CustomerGrowthJobDto {
    pub id: i64,
    pub region: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub project_id: String,
    pub job_id: String,
    pub display_name: String,
    pub status: String,
    pub owner_user_id: String,
}
