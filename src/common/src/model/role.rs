use serde::{Deserialize, Serialize};

use super::{AuthorizationConditionSpec, EvaluationContext};
use crate::ResourceUrn;

/// HTTP tuple to canonical resource mapping owned by an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRouteMatcher {
    pub id: String,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    pub path: String,
    pub resource_urn: String,
    #[serde(default)]
    pub parent_urns: Vec<String>,
}

/// An operation persisted in `iam_action`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IamActionInfo {
    pub identifier: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub route_matchers: Vec<HttpRouteMatcher>,
}

/// A role persisted in `iam_role` with its action identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IamRoleInfo {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub action_ids: Vec<String>,
}

/// IamPrincipalInfo-to-role assignment persisted in `iam_role_binding`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IamRoleBindingInfo {
    pub id: String,
    pub principal_id: String,
    pub role_id: String,
    pub effect: Effect,
    pub resource_urn: String,
    #[serde(default)]
    pub conditions: AuthorizationConditionSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub principal_id: String,
    #[serde(default)]
    pub group_principal_ids: Vec<String>,
    pub action: String,
    pub resource_urn: ResourceUrn,
    #[serde(default)]
    pub parent_urns: Vec<ResourceUrn>,
    #[serde(default)]
    pub context: EvaluationContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationDecision {
    pub allowed: bool,
    pub reason: String,
    pub role_binding_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationScope {
    pub allow_resource_urns: Vec<String>,
    pub deny_resource_urns: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Effect {
    Allow,
    Deny,
}

impl Effect {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Deny => "DENY",
        }
    }
}
