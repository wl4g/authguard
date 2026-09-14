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
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Mutex;

    use super::*;
    use crate::model::ExternalIdentityKey;
    use async_trait::async_trait;
    use chrono::Utc;

    #[derive(Default)]
    struct MemoryRepository {
        state: Mutex<State>,
    }

    #[derive(Default)]
    struct State {
        bindings: BTreeMap<ExternalIdentityKey, IamPrincipalInfo>,
        providers: BTreeMap<String, BTreeSet<String>>,
    }

    #[async_trait]
    impl IdentityBindingRepository for MemoryRepository {
        async fn find_principal_by_identity(
            &self,
            identity: &ExternalIdentityKey,
        ) -> Result<Option<IamPrincipalInfo>, IdentityRepositoryError> {
            Ok(self.state.lock().expect("state").bindings.get(identity).cloned())
        }

        async fn create_principal_and_bind(
            &self,
            principal: &IamPrincipalInfo,
            identity: &ExternalIdentity,
        ) -> Result<IamPrincipalInfo, IdentityRepositoryError> {
            let mut state = self.state.lock().expect("state");
            let key = identity
                .key()
                .map_err(|error| IdentityRepositoryError::Backend(error.to_string()))?;
            state.bindings.insert(key, principal.clone());
            state
                .providers
                .entry(principal.id.clone())
                .or_default()
                .insert(identity.provider.clone());
            Ok(principal.clone())
        }

        async fn bind_identity(
            &self,
            principal_id: &str,
            identity: &ExternalIdentity,
        ) -> Result<IamPrincipalInfo, IdentityRepositoryError> {
            let mut state = self.state.lock().expect("state");
            let key = identity
                .key()
                .map_err(|error| IdentityRepositoryError::Backend(error.to_string()))?;
            if state.bindings.contains_key(&key) {
                return Err(IdentityRepositoryError::IdentityAlreadyBound);
            }
            let principal = state
                .bindings
                .values()
                .find(|principal| principal.id == principal_id)
                .cloned()
                .ok_or_else(|| IdentityRepositoryError::Backend("missing principal".into()))?;
            state.bindings.insert(key, principal.clone());
            state
                .providers
                .entry(principal.id.clone())
                .or_default()
                .insert(identity.provider.clone());
            Ok(principal)
        }

        async fn principal_has_provider(
            &self,
            principal_id: &str,
            provider: &str,
        ) -> Result<bool, IdentityRepositoryError> {
            Ok(self
                .state
                .lock()
                .expect("state")
                .providers
                .get(principal_id)
                .is_some_and(|providers| providers.contains(provider)))
        }
    }

    fn identity(provider: &str, subject: &str) -> ExternalIdentity {
        ExternalIdentity {
            provider: provider.to_string(),
            issuer: format!("https://{provider}.example"),
            subject: subject.to_string(),
            claims: BTreeMap::new(),
        }
    }

    fn authentication(provider: &str, subject: &str) -> AuthenticationResult {
        AuthenticationResult::new(identity(provider, subject), ["test"], None, Utc::now())
    }

    fn service() -> AccountLinkingService<MemoryRepository> {
        AccountLinkingService::new(
            AccountLinkingProperties {
                strategy: LinkingStrategy::Explicit,
                authoritative_providers: BTreeSet::from(["corporate-dsp".to_string()]),
                allow_link: BTreeMap::from([(
                    "corporate-dsp".to_string(),
                    BTreeSet::from(["github".to_string(), "wechat".to_string()]),
                )]),
            },
            MemoryRepository::default(),
        )
    }

    #[tokio::test]
    async fn explicit_strategy_rejects_unbound_secondary_login() {
        let service = service();
        let result =
            service.resolve_login(&authentication("github", "987654"), PrincipalKind::User).await;
        assert!(matches!(result, Err(AccountLinkingError::AuthoritativeLoginRequired { .. })));
    }

    #[tokio::test]
    async fn explicit_link_converges_two_identities_on_one_principal() {
        let service = service();
        let corporate = service
            .resolve_login(&authentication("corporate-dsp", "EMP00123"), PrincipalKind::User)
            .await
            .expect("authoritative login");
        let github = service
            .link_identity(&corporate.principal_id, &authentication("github", "987654"))
            .await
            .expect("link GitHub");
        let later_login = service
            .resolve_login(&authentication("github", "987654"), PrincipalKind::User)
            .await
            .expect("GitHub login");

        assert_eq!(github.principal_id, corporate.principal_id);
        assert_eq!(later_login.principal_id, corporate.principal_id);
    }

    #[tokio::test]
    async fn first_login_reuses_one_identity_but_never_merges_providers_by_email() {
        let service = AccountLinkingService::new(
            AccountLinkingProperties {
                strategy: LinkingStrategy::FirstLogin,
                ..AccountLinkingProperties::default()
            },
            MemoryRepository::default(),
        );
        let mut github = authentication("github", "987654");
        github
            .external_identity
            .claims
            .insert("email".to_string(), serde_json::json!("alice@example.com"));
        let mut wechat = authentication("wechat", "openid-123");
        wechat
            .external_identity
            .claims
            .insert("email".to_string(), serde_json::json!("alice@example.com"));

        let first =
            service.resolve_login(&github, PrincipalKind::User).await.expect("first GitHub login");
        let repeated = service
            .resolve_login(&github, PrincipalKind::User)
            .await
            .expect("repeated GitHub login");
        let other_provider =
            service.resolve_login(&wechat, PrincipalKind::User).await.expect("first WeChat login");

        assert_eq!(repeated.principal_id, first.principal_id);
        assert_ne!(other_provider.principal_id, first.principal_id);
    }

    #[tokio::test]
    async fn linking_preserves_protocol_supplied_authentication_metadata() {
        let service = AccountLinkingService::new(
            AccountLinkingProperties {
                strategy: LinkingStrategy::FirstLogin,
                ..AccountLinkingProperties::default()
            },
            MemoryRepository::default(),
        );
        let authentication = AuthenticationResult::new(
            identity("wallet", "eip155:1:0x0000000000000000000000000000000000000001"),
            ["wallet", "siwx", "eoa"],
            Some("urn:authguard:loa:wallet".to_string()),
            Utc::now(),
        );

        let context = service
            .resolve_login(&authentication, PrincipalKind::User)
            .await
            .expect("wallet login");

        assert_eq!(context.amr, ["wallet", "siwx", "eoa"]);
        assert_eq!(context.acr.as_deref(), Some("urn:authguard:loa:wallet"));
    }
}
