use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    ExternalPrincipalRef, IPrincipalDiscovery, PrincipalDiscoveryError, PrincipalProjection,
};
use crate::model::PrincipalKind;

/// A normalized subset of the SCIM User resource.
///
/// Schema: RFC 7643 <https://www.rfc-editor.org/rfc/rfc7643.html>.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimUserResource {
    pub id: String,
    /// Canonical external identity key (normally the OIDC `sub`).
    ///
    /// RFC 7643 `externalId`: <https://www.rfc-editor.org/rfc/rfc7643.html#section-3.1>
    #[serde(default, rename = "externalId")]
    pub external_id: Option<String>,
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub emails: Vec<ScimEmail>,
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimEmail {
    pub value: String,
    #[serde(default)]
    pub primary: bool,
}

/// A normalized subset of the SCIM Group resource.
///
/// Schema: RFC 7643 <https://www.rfc-editor.org/rfc/rfc7643.html>.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimGroupResource {
    pub id: String,
    /// Canonical provider group identifier when it differs from the SCIM resource id.
    #[serde(default, rename = "externalId")]
    pub external_id: Option<String>,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
}

/// One SCIM provisioning change accepted by Authguard.
///
/// Protocol: RFC 7644 <https://www.rfc-editor.org/rfc/rfc7644.html>.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "resource", rename_all = "snake_case")]
pub enum ScimRefreshRequest {
    UpsertUser(ScimUserResource),
    UpsertGroup(ScimGroupResource),
    Delete(ExternalPrincipalRef),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimProjectionEvent {
    Upsert(PrincipalProjection),
    Delete(ExternalPrincipalRef),
}

/// Strongly typed SCIM discovery/provisioning adapter.
///
/// It only normalizes protocol resources. Persistence and authorization-cache
/// invalidation remain the handler's responsibility.
///
/// SCIM is the industry-standard provisioning protocol and is widely adopted
/// across identity vendors: AWS IAM Identity Center supports automatic user
/// provisioning via SCIM, for example:
/// <https://docs.aws.amazon.com/singlesignon/latest/userguide/provision-automatically.html>
#[derive(Debug, Clone)]
pub struct ScimPrincipalDiscovery {
    discovery_id: String,
    issuer: String,
}

impl ScimPrincipalDiscovery {
    /// Creates a SCIM adapter for one authoritative external issuer.
    ///
    /// # Errors
    ///
    /// Rejects blank identifiers or issuers.
    pub fn new(
        discovery_id: impl Into<String>,
        issuer: impl Into<String>,
    ) -> Result<Self, PrincipalDiscoveryError> {
        let discovery_id = discovery_id.into();
        let issuer = issuer.into();
        if discovery_id.trim().is_empty() || discovery_id.trim() != discovery_id {
            return Err(PrincipalDiscoveryError::InvalidConfiguration(
                "SCIM discovery id must be canonical and non-empty".to_string(),
            ));
        }
        if issuer.trim().is_empty() || issuer.trim() != issuer {
            return Err(PrincipalDiscoveryError::InvalidConfiguration(
                "SCIM issuer must be canonical and non-empty".to_string(),
            ));
        }
        Ok(Self { discovery_id, issuer })
    }

    /// Normalizes one SCIM change through the common discovery contract.
    ///
    /// # Errors
    ///
    /// Returns a validation error for malformed resources.
    pub async fn refresh(
        &self,
        request: ScimRefreshRequest,
    ) -> Result<ScimProjectionEvent, PrincipalDiscoveryError> {
        self.discover(request).await
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
impl IPrincipalDiscovery<ScimRefreshRequest> for ScimPrincipalDiscovery {
    type Output = ScimProjectionEvent;

    fn provider(&self) -> &'static str {
        "SCIM"
    }

    fn provider_id(&self) -> &str {
        &self.discovery_id
    }

    async fn discover(
        &self,
        request: ScimRefreshRequest,
    ) -> Result<Self::Output, PrincipalDiscoveryError> {
        match request {
            ScimRefreshRequest::UpsertUser(user) => {
                require_identifier("SCIM User id", &user.id)?;
                require_identifier("SCIM userName", &user.user_name)?;
                let external_id = user.external_id.as_deref().unwrap_or(&user.id);
                require_identifier("SCIM User externalId", external_id)?;
                let display_name = user
                    .display_name
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| user.user_name.clone());
                let email = user
                    .emails
                    .iter()
                    .find(|email| email.primary)
                    .or_else(|| user.emails.first())
                    .map(|email| email.value.clone());
                Ok(ScimProjectionEvent::Upsert(PrincipalProjection {
                    reference: self.reference(external_id.to_string()),
                    kind: PrincipalKind::User,
                    display_name,
                    username: Some(user.user_name),
                    email,
                    enabled: user.active.unwrap_or(true),
                    attributes: user.attributes,
                }))
            }
            ScimRefreshRequest::UpsertGroup(group) => {
                require_identifier("SCIM Group id", &group.id)?;
                require_identifier("SCIM Group displayName", &group.display_name)?;
                let external_id = group.external_id.as_deref().unwrap_or(&group.id);
                let external_id = external_id.strip_prefix("group:").unwrap_or(external_id);
                require_identifier("SCIM Group externalId", external_id)?;
                Ok(ScimProjectionEvent::Upsert(PrincipalProjection {
                    reference: self.reference(format!("group:{external_id}")),
                    kind: PrincipalKind::Group,
                    display_name: group.display_name,
                    username: None,
                    email: None,
                    enabled: true,
                    attributes: group.attributes,
                }))
            }
            ScimRefreshRequest::Delete(reference) => {
                if reference.provider_id != self.discovery_id || reference.issuer != self.issuer {
                    return Err(PrincipalDiscoveryError::InvalidQuery(
                        "SCIM delete reference does not belong to this discovery source"
                            .to_string(),
                    ));
                }
                require_identifier("SCIM external id", &reference.external_id)?;
                Ok(ScimProjectionEvent::Delete(reference))
            }
        }
    }

    async fn resolve_principal(
        &self,
        _reference: &ExternalPrincipalRef,
    ) -> Result<Option<PrincipalProjection>, PrincipalDiscoveryError> {
        Err(PrincipalDiscoveryError::InvalidQuery(
            "SCIM ingestion does not search external identity stores".to_string(),
        ))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refreshes_users_and_groups_with_stable_external_keys() {
        let discovery = ScimPrincipalDiscovery::new(
            "corporate-scim",
            "https://identity.example.com/scim/customer-growth",
        )
        .expect("discovery");
        let user = discovery
            .refresh(ScimRefreshRequest::UpsertUser(ScimUserResource {
                id: "user-42".to_string(),
                external_id: Some("oidc-sub-42".to_string()),
                user_name: "alice".to_string(),
                display_name: Some("Alice Analyst".to_string()),
                active: Some(true),
                emails: Vec::new(),
                attributes: BTreeMap::new(),
            }))
            .await
            .expect("user");
        let group = discovery
            .refresh(ScimRefreshRequest::UpsertGroup(ScimGroupResource {
                id: "growth-team".to_string(),
                external_id: Some("group:growth-team-uuid".to_string()),
                display_name: "Growth Team".to_string(),
                attributes: BTreeMap::new(),
            }))
            .await
            .expect("group");

        let ScimProjectionEvent::Upsert(user) = user else { panic!("upsert user") };
        let ScimProjectionEvent::Upsert(group) = group else { panic!("upsert group") };
        assert_eq!(user.reference.external_id, "oidc-sub-42");
        assert_eq!(group.reference.external_id, "group:growth-team-uuid");
    }
}
