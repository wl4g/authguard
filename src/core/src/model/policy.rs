use serde::{Deserialize, Serialize};

use super::{Action, AuthorizationConditionSpec, Effect, Role};

/// The active authorization policy aggregate.
///
/// Principal projections deliberately do not belong to this aggregate: a deployment may
/// discover millions of principals while the active authorization catalog remains small.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    #[serde(default)]
    pub revision: u64,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub actions: Vec<Action>,
    #[serde(default)]
    pub roles: Vec<Role>,
    #[serde(default)]
    pub role_bindings: Vec<RoleBinding>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            id: "default".to_string(),
            revision: 0,
            name: "Default authorization policy".to_string(),
            description: String::new(),
            actions: Vec::new(),
            roles: Vec::new(),
            role_bindings: Vec::new(),
        }
    }
}

/// Binds exactly one Principal to exactly one Role within a Resource URN scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleBinding {
    pub id: String,
    pub principal_id: String,
    pub role_id: String,
    pub effect: Effect,
    pub resource_urn: String,
    #[serde(default)]
    pub conditions: AuthorizationConditionSpec,
}

/// Maps an application HTTP tuple to a Resource URN template.
///
/// The Action is supplied by the owning [`Action`] record; it is intentionally not duplicated
/// inside the matcher.
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
