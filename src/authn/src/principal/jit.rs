//! JIT Principal resolution and protocol-independent external-identity linking.

use std::collections::BTreeMap;

use authguard_common::storage::{IdentityBindingRepository, IdentityRepositoryError};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore as _;
use thiserror::Error;

use crate::config::{AccountLinkingProperties, LinkingStrategy};
use crate::model::{
    AuthenticatedPrincipalContext, AuthenticationResult, ExternalIdentity, IamPrincipalInfo,
    IdentityModelError, PrincipalKind, PrincipalStatus,
};

/// JIT Principal materialization used by consumer/2C deployments.
///
/// The linking policy remains the safety gate: explicit mode only creates
/// from authoritative providers, while `first-login` permits social-first
/// creation. Equal email addresses are never considered a binding key.
pub struct JitPrincipalDiscovery<R> {
    linking: AccountLinkingService<R>,
}

impl<R> JitPrincipalDiscovery<R>
where
    R: IdentityBindingRepository,
{
    #[must_use]
    pub const fn new(policy: AccountLinkingProperties, repository: R) -> Self {
        Self { linking: AccountLinkingService::new(policy, repository) }
    }

    /// Resolves or materializes a canonical Principal under the linking policy.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identities, rejected linking, or storage failure.
    pub async fn discover(
        &self,
        authentication: &AuthenticationResult,
        kind: PrincipalKind,
    ) -> Result<AuthenticatedPrincipalContext, AccountLinkingError> {
        self.linking.resolve_login(authentication, kind).await
    }
}

/// Resolves normalized identities to one stable Authguard Principal.
pub struct AccountLinkingService<R> {
    policy: AccountLinkingProperties,
    repository: R,
}

impl<R> AccountLinkingService<R>
where
    R: IdentityBindingRepository,
{
    #[must_use]
    pub const fn new(policy: AccountLinkingProperties, repository: R) -> Self {
        Self { policy, repository }
    }

    /// Resolves login. Explicit mode creates only from an authoritative
    /// provider; an unbound secondary login must first authenticate through an
    /// authoritative provider and use [`Self::link_identity`].
    ///
    /// # Errors
    ///
    /// Fails for invalid identities, disabled Principals, unbound secondary
    /// identities, uniqueness conflicts, or repository failures.
    pub async fn resolve_login(
        &self,
        authentication: &AuthenticationResult,
        kind: PrincipalKind,
    ) -> Result<AuthenticatedPrincipalContext, AccountLinkingError> {
        let identity = &authentication.external_identity;
        let started = std::time::Instant::now();
        tracing::info!(
            event = "authguard.authn.account_linking.started",
            provider = %identity.provider,
            strategy = ?self.policy.strategy,
            "account-linking resolution started"
        );
        let key = identity.key()?;
        let (principal, outcome) =
            if let Some(principal) = self.repository.find_principal_by_identity(&key).await? {
                (principal, "existing_binding")
            } else if self.policy.strategy == LinkingStrategy::FirstLogin
                || self.policy.authoritative_providers.contains(&identity.provider)
            {
                let principal = new_principal(identity, kind);
                (self.repository.create_principal_and_bind(&principal, identity).await?, "created")
            } else {
                tracing::warn!(
                    event = "authguard.authn.account_linking.rejected",
                    provider = %identity.provider,
                    reason = "authoritative_login_required",
                    duration_seconds = started.elapsed().as_secs_f64(),
                    "unbound secondary identity rejected"
                );
                return Err(AccountLinkingError::AuthoritativeLoginRequired {
                    provider: identity.provider.clone(),
                });
            };
        let context = Self::context(principal, authentication)?;
        tracing::info!(
            event = "authguard.authn.account_linking.succeeded",
            provider = %identity.provider,
            principal_id = %context.principal_id,
            outcome,
            duration_seconds = started.elapsed().as_secs_f64(),
            "external identity resolved to canonical Principal"
        );
        Ok(context)
    }

    /// Explicitly binds a newly authenticated external identity to the
    /// already authenticated canonical Principal.
    ///
    /// # Errors
    ///
    /// Rejects policy-disallowed links and globally conflicting bindings.
    pub async fn link_identity(
        &self,
        authenticated_principal_id: &str,
        authentication: &AuthenticationResult,
    ) -> Result<AuthenticatedPrincipalContext, AccountLinkingError> {
        let identity = &authentication.external_identity;
        let started = std::time::Instant::now();
        tracing::info!(
            event = "authguard.authn.account_link.started",
            provider = %identity.provider,
            principal_id = authenticated_principal_id,
            "explicit account link started"
        );
        let _ = identity.key()?;
        let mut permitted = false;
        for (authoritative, secondary) in &self.policy.allow_link {
            if secondary.contains(&identity.provider)
                && self
                    .repository
                    .principal_has_provider(authenticated_principal_id, authoritative)
                    .await?
            {
                permitted = true;
                break;
            }
        }
        if !permitted {
            tracing::warn!(
                event = "authguard.authn.account_link.rejected",
                provider = %identity.provider,
                principal_id = authenticated_principal_id,
                reason = "link_not_allowed",
                duration_seconds = started.elapsed().as_secs_f64(),
                "explicit account link rejected"
            );
            return Err(AccountLinkingError::LinkNotAllowed {
                provider: identity.provider.clone(),
            });
        }
        let principal = self.repository.bind_identity(authenticated_principal_id, identity).await?;
        let context = Self::context(principal, authentication)?;
        tracing::info!(
            event = "authguard.authn.account_link.succeeded",
            provider = %identity.provider,
            principal_id = %context.principal_id,
            duration_seconds = started.elapsed().as_secs_f64(),
            "external identity linked"
        );
        Ok(context)
    }

    /// Removes a binding created for a registration whose credential write
    /// failed, deleting the Principal only when it has no remaining identities.
    pub(crate) async fn rollback_identity_binding(
        &self,
        principal_id: &str,
        identity: &crate::model::ExternalIdentityKey,
    ) -> Result<(), AccountLinkingError> {
        self.repository.rollback_identity_binding(principal_id, identity).await?;
        Ok(())
    }

    fn context(
        principal: IamPrincipalInfo,
        authentication: &AuthenticationResult,
    ) -> Result<AuthenticatedPrincipalContext, AccountLinkingError> {
        if principal.status != PrincipalStatus::Active {
            return Err(AccountLinkingError::PrincipalDisabled(principal.id));
        }
        Ok(AuthenticatedPrincipalContext {
            principal_id: principal.id,
            kind: principal.kind,
            stable_group_ids: Vec::new(),
            // Authentication-side claims (email, wallet metadata, IdP data)
            // never cross the Principal/AuthZ boundary.
            trusted_claims: std::collections::HashMap::new(),
            acr: authentication.acr.clone(),
            amr: authentication.amr.clone(),
        })
    }
}

fn new_principal(identity: &ExternalIdentity, kind: PrincipalKind) -> IamPrincipalInfo {
    let mut random = [0_u8; 18];
    rand::rng().fill_bytes(&mut random);
    let display_name = ["display_name", "username", "email"]
        .iter()
        .find_map(|name| identity.claims.get(*name).and_then(serde_json::Value::as_str))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&identity.subject)
        .to_string();
    IamPrincipalInfo {
        id: format!("P_{}", URL_SAFE_NO_PAD.encode(random)),
        kind,
        display_name,
        status: PrincipalStatus::Active,
        authorization_state: BTreeMap::default(),
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AccountLinkingError {
    #[error(transparent)]
    InvalidIdentity(#[from] IdentityModelError),
    #[error("unbound provider `{provider}` requires authoritative login before linking")]
    AuthoritativeLoginRequired { provider: String },
    #[error("linking provider `{provider}` is not allowed for this Principal")]
    LinkNotAllowed { provider: String },
    #[error("Principal `{0}` is disabled")]
    PrincipalDisabled(String),
    #[error("external identity is already bound to another Principal")]
    IdentityAlreadyBound,
    #[error("account-linking repository failed: {0}")]
    Repository(String),
}

impl From<IdentityRepositoryError> for AccountLinkingError {
    fn from(error: IdentityRepositoryError) -> Self {
        match error {
            IdentityRepositoryError::IdentityAlreadyBound => Self::IdentityAlreadyBound,
            IdentityRepositoryError::Backend(message) => Self::Repository(message),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/principal/jit.rs"]
mod tests;
