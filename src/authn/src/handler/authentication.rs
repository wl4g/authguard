//! Protocol-neutral authentication convergence and runtime composition.

use std::sync::Arc;

use authguard_common::cache::ICache;
use authguard_common::config::AppConfig;
use authguard_common::model::{AuthenticatedPrincipalContext, AuthenticationResult, PrincipalKind};
use authguard_common::storage::{IdentityBindingRepository, StandaloneCredentialRepository};
use thiserror::Error;

use crate::authentication::{TokenError, TokenIssuer};
use crate::AccountLinkingProperties;

use crate::principal::{AccountLinkingError, AccountLinkingService};

/// The sole convergence point after protocol-specific proof verification.
pub(crate) struct AuthenticationPipeline {
    linking: AccountLinkingService<Arc<dyn IdentityBindingRepository>>,
    tokens: TokenIssuer,
}

/// Canonical Principal plus the one unified `AuthGuard` bearer token.
pub(crate) struct IssuedAuthentication {
    pub access_token: String,
    pub expires_in: u64,
    pub principal: AuthenticatedPrincipalContext,
}

#[derive(Debug, Error)]
pub(crate) enum AuthenticationPipelineError {
    #[error(transparent)]
    Linking(#[from] AccountLinkingError),
    #[error(transparent)]
    Token(#[from] TokenError),
}

impl AuthenticationPipeline {
    fn new(
        policy: AccountLinkingProperties,
        identities: Arc<dyn IdentityBindingRepository>,
        tokens: TokenIssuer,
    ) -> Self {
        Self { linking: AccountLinkingService::new(policy, identities), tokens }
    }

    /// Resolves a verified identity and issues the canonical token.
    pub(crate) async fn login(
        &self,
        authentication: AuthenticationResult,
        kind: PrincipalKind,
    ) -> Result<IssuedAuthentication, AuthenticationPipelineError> {
        let principal = self.linking.resolve_login(&authentication, kind).await?;
        self.issue(&authentication, principal)
    }

    /// Explicitly links a verified identity and issues the canonical token.
    pub(crate) async fn link(
        &self,
        principal_id: &str,
        authentication: AuthenticationResult,
    ) -> Result<IssuedAuthentication, AuthenticationPipelineError> {
        let principal = self.linking.link_identity(principal_id, &authentication).await?;
        self.issue(&authentication, principal)
    }

    /// Validates an existing `AuthGuard` bearer token for explicit linking.
    pub(crate) fn authenticate_token(
        &self,
        headers: &axum::http::HeaderMap,
    ) -> Result<String, TokenError> {
        self.tokens.authenticate_bearer(headers)
    }

    fn issue(
        &self,
        authentication: &AuthenticationResult,
        principal: AuthenticatedPrincipalContext,
    ) -> Result<IssuedAuthentication, AuthenticationPipelineError> {
        let access_token = self.tokens.issue(&principal, authentication)?;
        Ok(IssuedAuthentication {
            access_token,
            expires_in: self.tokens.ttl().as_secs(),
            principal,
        })
    }
}

/// Shared runtime dependencies; protocol implementations only borrow what they own.
#[derive(Clone)]
pub(crate) struct AuthnRuntime {
    pub pipeline: Arc<AuthenticationPipeline>,
    pub credentials: Arc<dyn StandaloneCredentialRepository>,
    pub challenges: Option<Arc<dyn ICache>>,
}

impl AuthnRuntime {
    /// Opens protocol-neutral persistence, challenge storage, linking, and token issuance.
    pub(crate) async fn open() -> anyhow::Result<Self> {
        let config = AppConfig::get();
        let storage = config.get_storage();
        let (identities, credentials): (
            Arc<dyn IdentityBindingRepository>,
            Arc<dyn StandaloneCredentialRepository>,
        ) = match storage.provider.to_ascii_lowercase().as_str() {
            "sqlite" => {
                let repository = Arc::new(
                    authguard_common::storage::AuthnSqliteRepository::connect(&storage.sqlite)
                        .await?,
                );
                (repository.clone(), repository)
            }
            "postgres" => {
                let repository = Arc::new(
                    authguard_common::storage::AuthnPostgresRepository::connect(&storage.postgres)
                        .await?,
                );
                (repository.clone(), repository)
            }
            provider => anyhow::bail!("unsupported IAM storage provider `{provider}`"),
        };
        let authn = config.get_authn();
        let challenge_required = !authn.providers.is_empty()
            || authn.wallet.enabled
            || authn.standalone.enabled
                && (authn.standalone.totp.enabled || authn.standalone.webauthn.enabled);
        let challenges = if challenge_required {
            Some(authguard_common::cache::open_cache().await?)
        } else {
            None
        };
        let tokens = TokenIssuer::from_config(authn)?;
        let pipeline = Arc::new(AuthenticationPipeline::new(
            authn.account_linking.clone(),
            identities,
            tokens,
        ));
        Ok(Self { pipeline, credentials, challenges })
    }
}
