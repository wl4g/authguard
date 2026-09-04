use serde::{Deserialize, Serialize};

use super::{EvaluationContext, HttpRouteMatcher, ResourceUrn};

/// A fully resolved authorization request evaluated against the current policy.
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

/// The policy decision for one principal, action, resource, and request context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationDecision {
    pub allowed: bool,
    pub reason: String,
    pub role_binding_id: Option<String>,
}

/// The resource expressions that bound one authorized action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationScope {
    pub allow_resource_urns: Vec<String>,
    pub deny_resource_urns: Vec<String>,
}

/// An operation that can be granted by a role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    pub identifier: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub route_matchers: Vec<HttpRouteMatcher>,
}

/// A named collection of action identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub action_ids: Vec<String>,
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
