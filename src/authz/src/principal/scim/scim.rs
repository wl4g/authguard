//! RFC-compatible SCIM 2.0 User and Group provisioning routes.
//!
//! Protocol references:
//! - RFC 7644 resource endpoints and methods:
//!   <https://www.rfc-editor.org/rfc/rfc7644.html#section-3.2>
//! - RFC 7644 create, retrieve, replace, PATCH, and delete semantics:
//!   <https://www.rfc-editor.org/rfc/rfc7644.html#section-3.3>
//!   <https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4>
//!   <https://www.rfc-editor.org/rfc/rfc7644.html#section-3.5>
//!   <https://www.rfc-editor.org/rfc/rfc7644.html#section-3.6>
//! - RFC 7643 User and Group core schemas:
//!   <https://www.rfc-editor.org/rfc/rfc7643.html#section-4.1>
//!   <https://www.rfc-editor.org/rfc/rfc7643.html#section-4.2>
//!
//! GitHub Enterprise SCIM integration reference:
//! <https://docs.github.com/en/enterprise-cloud@latest/rest/authentication/permissions-required-for-github-apps?apiVersion=2026-03-10#enterprise-permissions-for-enterprise-scim>
//!
//! `AuthGuard` supports the bounded provisioning profile implemented below;
//! unsupported complex PATCH paths and filters fail with a SCIM error instead
//! of being silently accepted.

use std::collections::BTreeMap;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore as _;
use serde_json::Value;

use super::super::{
    ExternalPrincipalRef, IPrincipalDiscovery, PrincipalDiscoveryError, PrincipalProjection,
};
use super::model::{
    ScimGroupResource, ScimListQuery, ScimListResponse, ScimMeta, ScimPatchRequest, ScimPatchVerb,
    ScimUserResource, GROUP_SCHEMA, LIST_SCHEMA, PATCH_SCHEMA, USER_SCHEMA,
};
use crate::model::{ExternalIdentityKey, IamPrincipalInfo, PrincipalKind, PrincipalStatus};

#[derive(Debug, Clone)]
pub struct ScimPrincipalDiscovery {
    discovery_id: String,
    issuer: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimProvisioningRequest {
    UpsertUser { principal_id: String, resource: ScimUserResource },
    UpsertGroup { principal_id: String, resource: ScimGroupResource },
    Delete { principal_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimProjectionEvent {
    Upsert { principal_id: String, projection: PrincipalProjection },
    Delete { principal_id: String },
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
pub enum ScimResource {
    User(ScimUserResource),
    Group(ScimGroupResource),
}

impl ScimResource {
    #[must_use]
    pub const fn kind(&self) -> PrincipalKind {
        match self {
            Self::User(_) => PrincipalKind::User,
            Self::Group(_) => PrincipalKind::Group,
        }
    }

    #[must_use]
    pub fn location(&self) -> Option<&str> {
        match self {
            Self::User(resource) => resource.meta.as_ref(),
            Self::Group(resource) => resource.meta.as_ref(),
        }
        .map(|meta| meta.location.as_str())
    }

    #[must_use]
    pub fn into_upsert(self, principal_id: String) -> ScimProvisioningRequest {
        match self {
            Self::User(resource) => ScimProvisioningRequest::UpsertUser { principal_id, resource },
            Self::Group(resource) => {
                ScimProvisioningRequest::UpsertGroup { principal_id, resource }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScimStoredResource {
    pub principal: IamPrincipalInfo,
    pub claims: Value,
}

impl ScimPrincipalDiscovery {
    /// Creates one configured SCIM discovery adapter.
    ///
    /// # Errors
    ///
    /// Returns an error for a blank or non-canonical discovery ID or issuer.
    pub fn new(
        discovery_id: impl Into<String>,
        issuer: impl Into<String>,
    ) -> Result<Self, PrincipalDiscoveryError> {
        let discovery_id = discovery_id.into();
        let issuer = issuer.into();
        require_identifier("SCIM discovery id", &discovery_id)?;
        require_identifier("SCIM issuer", &issuer)?;
        Ok(Self { discovery_id, issuer })
    }

    /// Returns the exact identity-binding key represented by a pushed resource.
    ///
    /// # Errors
    ///
    /// Returns an error when an upsert lacks a stable `externalId`.
    pub fn upsert_identity_key(
        &self,
        request: &ScimProvisioningRequest,
    ) -> Result<ExternalIdentityKey, PrincipalDiscoveryError> {
        let subject = match request {
            ScimProvisioningRequest::UpsertUser { resource, .. } => {
                resource.external_id.clone().ok_or_else(|| {
                    PrincipalDiscoveryError::InvalidQuery(
                        "SCIM User externalId is required as the stable external subject"
                            .to_string(),
                    )
                })?
            }
            ScimProvisioningRequest::UpsertGroup { resource, .. } => {
                let external_id = resource.external_id.as_deref().ok_or_else(|| {
                    PrincipalDiscoveryError::InvalidQuery(
                        "SCIM Group externalId is required as the stable external subject"
                            .to_string(),
                    )
                })?;
                format!("group:{}", external_id.strip_prefix("group:").unwrap_or(external_id))
            }
            ScimProvisioningRequest::Delete { .. } => {
                return Err(PrincipalDiscoveryError::InvalidQuery(
                    "SCIM deletion has no external identity".to_string(),
                ));
            }
        };
        Ok(ExternalIdentityKey {
            provider: self.discovery_id.clone(),
            issuer: self.issuer.clone(),
            subject,
        })
    }

    /// Restores a protocol resource from its durable Principal identity claims.
    ///
    /// # Errors
    ///
    /// Returns an error for corrupt claims or an unsupported Workload Principal.
    pub fn restore_resource(
        &self,
        stored: ScimStoredResource,
    ) -> Result<ScimResource, PrincipalDiscoveryError> {
        match stored.principal.kind {
            PrincipalKind::User => {
                let mut resource: ScimUserResource = serde_json::from_value(stored.claims)
                    .map_err(|error| PrincipalDiscoveryError::InvalidQuery(error.to_string()))?;
                resource.id = Some(stored.principal.id.clone());
                if !resource.schemas.iter().any(|schema| schema == USER_SCHEMA) {
                    resource.schemas.insert(0, USER_SCHEMA.to_string());
                }
                resource.active = Some(stored.principal.status == PrincipalStatus::Active);
                resource.meta = Some(ScimMeta {
                    resource_type: "User".to_string(),
                    location: format!("/scim/v2/Users/{}", stored.principal.id),
                    created: None,
                    last_modified: None,
                    version: None,
                });
                Ok(ScimResource::User(resource))
            }
            PrincipalKind::Group => {
                let mut resource: ScimGroupResource = serde_json::from_value(stored.claims)
                    .map_err(|error| PrincipalDiscoveryError::InvalidQuery(error.to_string()))?;
                resource.id = Some(stored.principal.id.clone());
                if !resource.schemas.iter().any(|schema| schema == GROUP_SCHEMA) {
                    resource.schemas.insert(0, GROUP_SCHEMA.to_string());
                }
                resource.meta = Some(ScimMeta {
                    resource_type: "Group".to_string(),
                    location: format!("/scim/v2/Groups/{}", stored.principal.id),
                    created: None,
                    last_modified: None,
                    version: None,
                });
                Ok(ScimResource::Group(resource))
            }
            PrincipalKind::Workload => Err(PrincipalDiscoveryError::InvalidQuery(
                "SCIM User/Group endpoint cannot project a WORKLOAD Principal".to_string(),
            )),
        }
    }

    /// Applies the supported top-level RFC 7644 PATCH profile.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing `PatchOp` schema or unsupported path.
    pub fn patch(
        &self,
        resource: &ScimResource,
        patch: &ScimPatchRequest,
    ) -> Result<ScimResource, PrincipalDiscoveryError> {
        if patch.schemas != [PATCH_SCHEMA] {
            return Err(PrincipalDiscoveryError::InvalidQuery(
                "SCIM PATCH requires the PatchOp schema".to_string(),
            ));
        }
        let mut value = match &resource {
            ScimResource::User(resource) => serde_json::to_value(resource),
            ScimResource::Group(resource) => serde_json::to_value(resource),
        }
        .map_err(|error| PrincipalDiscoveryError::InvalidQuery(error.to_string()))?;
        for operation in &patch.operations {
            apply_patch_operation(&mut value, operation)?;
        }
        match resource {
            ScimResource::User(_) => serde_json::from_value(value)
                .map(ScimResource::User)
                .map_err(|error| PrincipalDiscoveryError::InvalidQuery(error.to_string())),
            ScimResource::Group(_) => serde_json::from_value(value)
                .map(ScimResource::Group)
                .map_err(|error| PrincipalDiscoveryError::InvalidQuery(error.to_string())),
        }
    }

    /// Applies the supported RFC 7644 filter and pagination profile.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported filter expression.
    pub fn list_page(
        &self,
        mut resources: Vec<ScimResource>,
        query: &ScimListQuery,
    ) -> Result<ScimListResponse<ScimResource>, PrincipalDiscoveryError> {
        if let Some(filter) = query.filter.as_deref() {
            let (attribute, expected) = parse_filter(filter)?;
            resources.retain(|resource| {
                serde_json::to_value(resource).is_ok_and(|value| {
                    value.get(attribute).and_then(Value::as_str) == Some(expected)
                })
            });
        }
        let total_results = resources.len();
        let start_index = query.start_index.max(1);
        let resources = resources
            .into_iter()
            .skip(start_index - 1)
            .take(query.count.min(100))
            .collect::<Vec<_>>();
        Ok(ScimListResponse {
            schemas: vec![LIST_SCHEMA.to_string()],
            total_results,
            start_index,
            items_per_page: resources.len(),
            resources,
        })
    }

    fn reference(&self, external_id: String) -> ExternalPrincipalRef {
        ExternalPrincipalRef {
            provider_id: self.discovery_id.clone(),
            issuer: self.issuer.clone(),
            external_id,
        }
    }
}

#[async_trait]
impl IPrincipalDiscovery<ScimProvisioningRequest> for ScimPrincipalDiscovery {
    type Output = ScimProjectionEvent;

    fn provider(&self) -> &'static str {
        "SCIM"
    }

    fn provider_id(&self) -> &str {
        &self.discovery_id
    }

    async fn discover(
        &self,
        request: ScimProvisioningRequest,
    ) -> Result<Self::Output, PrincipalDiscoveryError> {
        match request {
            ScimProvisioningRequest::UpsertUser { principal_id, mut resource } => {
                let principal_id = principal_id_or_new(principal_id)?;
                require_schema(&resource.schemas, USER_SCHEMA)?;
                require_identifier("SCIM userName", &resource.user_name)?;
                let external_id = resource.external_id.clone().ok_or_else(|| {
                    PrincipalDiscoveryError::InvalidQuery(
                        "SCIM User externalId is required as the stable external subject"
                            .to_string(),
                    )
                })?;
                require_identifier("SCIM User externalId", &external_id)?;
                let display_name = resource
                    .display_name
                    .clone()
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| resource.user_name.clone());
                resource.id = None;
                resource.meta = None;
                let claims = resource_claims(&resource)?;
                Ok(ScimProjectionEvent::Upsert {
                    principal_id,
                    projection: PrincipalProjection {
                        reference: self.reference(external_id),
                        kind: PrincipalKind::User,
                        display_name,
                        username: Some(resource.user_name),
                        email: resource
                            .emails
                            .iter()
                            .find(|email| email.primary)
                            .or_else(|| resource.emails.first())
                            .map(|email| email.value.clone()),
                        enabled: resource.active.unwrap_or(true),
                        attributes: claims,
                    },
                })
            }
            ScimProvisioningRequest::UpsertGroup { principal_id, mut resource } => {
                let principal_id = principal_id_or_new(principal_id)?;
                require_schema(&resource.schemas, GROUP_SCHEMA)?;
                require_identifier("SCIM Group displayName", &resource.display_name)?;
                let external_id = resource.external_id.clone().ok_or_else(|| {
                    PrincipalDiscoveryError::InvalidQuery(
                        "SCIM Group externalId is required as the stable external subject"
                            .to_string(),
                    )
                })?;
                let external_id = external_id.strip_prefix("group:").unwrap_or(&external_id);
                require_identifier("SCIM Group externalId", external_id)?;
                resource.id = None;
                resource.meta = None;
                let claims = resource_claims(&resource)?;
                Ok(ScimProjectionEvent::Upsert {
                    principal_id,
                    projection: PrincipalProjection {
                        reference: self.reference(format!("group:{external_id}")),
                        kind: PrincipalKind::Group,
                        display_name: resource.display_name,
                        username: None,
                        email: None,
                        enabled: true,
                        attributes: claims,
                    },
                })
            }
            ScimProvisioningRequest::Delete { principal_id } => {
                require_identifier("canonical Principal ID", &principal_id)?;
                Ok(ScimProjectionEvent::Delete { principal_id })
            }
        }
    }

    async fn resolve_principal(
        &self,
        _reference: &ExternalPrincipalRef,
    ) -> Result<Option<PrincipalProjection>, PrincipalDiscoveryError> {
        Ok(None)
    }
}

fn resource_claims(
    resource: &impl serde::Serialize,
) -> Result<BTreeMap<String, Value>, PrincipalDiscoveryError> {
    serde_json::to_value(resource)
        .map_err(|error| PrincipalDiscoveryError::InvalidQuery(error.to_string()))?
        .as_object()
        .cloned()
        .map(|values| values.into_iter().collect())
        .ok_or_else(|| {
            PrincipalDiscoveryError::InvalidQuery("SCIM resource must be an object".to_string())
        })
}

fn principal_id_or_new(value: String) -> Result<String, PrincipalDiscoveryError> {
    if !value.is_empty() {
        require_identifier("canonical Principal ID", &value)?;
        return Ok(value);
    }
    let mut random = [0_u8; 18];
    rand::rng().fill_bytes(&mut random);
    Ok(format!("P_{}", URL_SAFE_NO_PAD.encode(random)))
}

fn require_schema(schemas: &[String], expected: &str) -> Result<(), PrincipalDiscoveryError> {
    if schemas.iter().any(|schema| schema == expected) {
        Ok(())
    } else {
        Err(PrincipalDiscoveryError::InvalidQuery(format!(
            "SCIM resource requires schema `{expected}`"
        )))
    }
}

fn require_identifier(name: &str, value: &str) -> Result<(), PrincipalDiscoveryError> {
    if value.trim().is_empty() || value.trim() != value || value.len() > 512 {
        return Err(PrincipalDiscoveryError::InvalidQuery(format!(
            "{name} must contain 1 to 512 canonical bytes"
        )));
    }
    Ok(())
}

fn parse_filter(filter: &str) -> Result<(&str, &str), PrincipalDiscoveryError> {
    let (attribute, expected) = filter.split_once(" eq ").ok_or_else(invalid_filter)?;
    if !matches!(attribute, "externalId" | "userName" | "displayName") {
        return Err(invalid_filter());
    }
    expected
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .map(|expected| (attribute, expected))
        .ok_or_else(invalid_filter)
}

fn invalid_filter() -> PrincipalDiscoveryError {
    PrincipalDiscoveryError::InvalidQuery(
        "SCIM filter must be externalId, userName, or displayName eq a quoted string".to_string(),
    )
}

fn apply_patch_operation(
    resource: &mut Value,
    operation: &super::model::ScimPatchOperation,
) -> Result<(), PrincipalDiscoveryError> {
    let object = resource.as_object_mut().ok_or_else(|| {
        PrincipalDiscoveryError::InvalidQuery("SCIM PATCH target must be an object".to_string())
    })?;
    let path = operation.path.as_deref().ok_or_else(|| {
        PrincipalDiscoveryError::InvalidQuery(
            "SCIM PATCH operations require a top-level attribute path".to_string(),
        )
    })?;
    if !path.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'$') {
        return Err(PrincipalDiscoveryError::InvalidQuery(
            "complex SCIM PATCH paths are not supported".to_string(),
        ));
    }
    match operation.op {
        ScimPatchVerb::Remove => {
            object.remove(path);
        }
        ScimPatchVerb::Add | ScimPatchVerb::Replace => {
            object.insert(path.to_string(), operation.value.clone());
        }
    }
    Ok(())
}
