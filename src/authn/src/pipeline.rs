//! The only convergence point after protocol-specific authentication.

use std::sync::Arc;

use authguard_common::model::{AuthenticatedPrincipalContext, AuthenticationResult, PrincipalKind};
use authguard_common::storage::IdentityBindingRepository;
use thiserror::Error;

use crate::session::{SessionError, SessionIssuer};
use crate::{AccountLinkingError, AccountLinkingProperties, AccountLinkingService};

pub struct AuthenticationPipeline {
    linking: AccountLinkingService<Arc<dyn IdentityBindingRepository>>,
    sessions: SessionIssuer,
}

pub struct AuthenticatedSession {
    pub access_token: String,
    pub expires_in: u64,
    pub principal: AuthenticatedPrincipalContext,
}

#[derive(Debug, Error)]
pub enum AuthenticationPipelineError {
    #[error(transparent)]
    Linking(#[from] AccountLinkingError),
    #[error(transparent)]
    Session(#[from] SessionError),
}

impl AuthenticationPipeline {
    #[must_use]
    pub fn new(
        policy: AccountLinkingProperties,
        identities: Arc<dyn IdentityBindingRepository>,
        sessions: SessionIssuer,
    ) -> Self {
        Self { linking: AccountLinkingService::new(policy, identities), sessions }
    }

    /// Resolves a verified identity and issues the canonical session.
    ///
    /// # Errors
    ///
    /// Returns an error when linking is rejected or JWT issuance fails.
    pub async fn login(
        &self,
        authentication: AuthenticationResult,
        kind: PrincipalKind,
    ) -> Result<AuthenticatedSession, AuthenticationPipelineError> {
        let principal = self.linking.resolve_login(&authentication, kind).await?;
        self.session(&authentication, principal)
    }

    /// Explicitly links a verified identity and issues the canonical session.
    ///
    /// # Errors
    ///
    /// Returns an error when linking is rejected or JWT issuance fails.
    pub async fn link(
        &self,
        principal_id: &str,
        authentication: AuthenticationResult,
    ) -> Result<AuthenticatedSession, AuthenticationPipelineError> {
        let principal = self.linking.link_identity(principal_id, &authentication).await?;
        self.session(&authentication, principal)
    }

    /// Validates an existing `AuthGuard` bearer token for explicit linking.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, expired, or invalid canonical token.
    pub fn authenticate_session(
        &self,
        headers: &axum::http::HeaderMap,
    ) -> Result<String, SessionError> {
        self.sessions.authenticate_bearer(headers)
    }

    fn session(
        &self,
        authentication: &AuthenticationResult,
        principal: AuthenticatedPrincipalContext,
    ) -> Result<AuthenticatedSession, AuthenticationPipelineError> {
        let access_token = self.sessions.issue(&principal, authentication)?;
        Ok(AuthenticatedSession {
            access_token,
            expires_in: self.sessions.ttl().as_secs(),
            principal,
        })
    }
}
