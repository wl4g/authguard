use serde::{Deserialize, Serialize};

use super::EvaluationContext;

// The generated tonic client/server surface follows upstream code-generation
// conventions that cannot satisfy this workspace's documentation-style lints.
#[allow(clippy::default_trait_access, clippy::doc_markdown, clippy::missing_errors_doc)]
pub mod access_context_v1 {
    tonic::include_proto!("authguard.access.v1");
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

impl ApiError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self { code: code.into(), message: message.into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizePayload {
    pub principal_id: String,
    #[serde(default)]
    pub group_principal_ids: Vec<String>,
    pub action: String,
    pub resource_urn: String,
    #[serde(default)]
    pub parent_urns: Vec<String>,
    #[serde(default)]
    pub context: EvaluationContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeResponse {
    pub allowed: bool,
    pub reason: String,
    pub role_binding_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub status: String,
    pub policy_revision: u64,
    pub actions: usize,
    pub roles: usize,
    pub role_bindings: usize,
    pub route_matchers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceCollectionResponse<T> {
    pub policy_revision: u64,
    pub total: usize,
    pub items: Vec<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceResponse<T> {
    pub policy_revision: u64,
    pub resource: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalCollectionResponse<T> {
    pub total: usize,
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}
