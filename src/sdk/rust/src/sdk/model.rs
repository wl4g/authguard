pub use authguard_common::{AccessContext, AccessContextError, AccessContextInput};
pub use authguard_common::{
    PathMap, PathPattern, ResourceSqlMapping, ResourceUrn, SegmentMap, SegmentPattern, SqlScope,
    UrnPattern,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessGrantSet {
    pub allow_resource_urns: Vec<String>,
    pub deny_resource_urns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestAccess {
    pub principal_id: String,
    pub action: String,
    pub resource_urn: String,
    pub grants: AccessGrantSet,
}

impl RequestAccess {
    #[must_use]
    pub fn from_context(context: &AccessContext) -> Self {
        Self {
            principal_id: context.principal_id.clone(),
            action: context.action.clone(),
            resource_urn: context.resource_urn.clone(),
            grants: AccessGrantSet::from_context(context),
        }
    }

    #[must_use]
    pub fn from_grants(grants: AccessGrantSet) -> Self {
        Self {
            principal_id: String::new(),
            action: String::new(),
            resource_urn: String::new(),
            grants,
        }
    }
}

impl AccessGrantSet {
    #[must_use]
    pub fn new(allow_resource_urns: Vec<String>, deny_resource_urns: Vec<String>) -> Self {
        Self { allow_resource_urns, deny_resource_urns }
    }

    #[must_use]
    pub fn empty() -> Self {
        Self { allow_resource_urns: Vec::new(), deny_resource_urns: Vec::new() }
    }

    #[must_use]
    pub fn from_context(context: &AccessContext) -> Self {
        Self::new(context.allow_resource_urns.clone(), context.deny_resource_urns.clone())
    }
}
