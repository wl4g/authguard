mod github;
mod google;
mod normalization;
mod oauth_like;
mod oidc;
mod qq;
mod transport;
mod wechat;

use async_trait::async_trait;
use thiserror::Error;

use crate::model::ExternalIdentity;
use authguard_common::PrincipalKind;

/// Validated values received from an OAuth/OAuth-like callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthLikeCallback {
    pub authorization_code: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub client_secret: String,
    pub nonce: Option<String>,
    pub pkce_verifier: Option<String>,
}

pub struct ProviderAuthorization {
    pub url: reqwest::Url,
    pub nonce: Option<String>,
    pub pkce_verifier: Option<String>,
}

/// Minimal provider SPI: authenticate and normalize one external identity.
#[async_trait]
pub trait IProviderAdapter: Send + Sync {
    fn provider_id(&self) -> &str;
    /// Builds the authorization redirect for one provider flow.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider authorization endpoint is invalid.
    fn authorization_url(
        &self,
        client_id: &str,
        redirect_uri: &str,
        state: &str,
    ) -> Result<reqwest::Url, ProviderError>;

    /// Builds authorization metadata used by state persistence and callback validation.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider authorization endpoint is invalid.
    fn authorize(
        &self,
        client_id: &str,
        redirect_uri: &str,
        state: &str,
    ) -> Result<ProviderAuthorization, ProviderError> {
        Ok(ProviderAuthorization {
            url: self.authorization_url(client_id, redirect_uri, state)?,
            nonce: None,
            pkce_verifier: None,
        })
    }
    async fn authenticate(
        &self,
        callback: OAuthLikeCallback,
    ) -> Result<ExternalIdentity, ProviderError>;

    /// Normalizes a bearer token issued by the configured OIDC provider.
    /// OAuth-like adapters reject this flow unless their SPI overrides it.
    async fn authenticate_bearer(
        &self,
        _access_token: &str,
        _kind: PrincipalKind,
    ) -> Result<ExternalIdentity, ProviderError> {
        Err(ProviderError::UnsupportedFlow)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProviderError {
    #[error("invalid provider configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("provider token response does not contain an access token")]
    MissingAccessToken,
    #[error("provider identity response does not contain a stable subject")]
    MissingSubject,
    #[error("provider ID token validation failed")]
    InvalidIdentityToken,
    #[error("provider does not support this authentication flow")]
    UnsupportedFlow,
    #[error("provider transport failed: {0}")]
    Transport(String),
    #[error("provider rejected the request with HTTP {0}")]
    ProviderRejected(u16),
}

impl ProviderError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InvalidConfiguration(_) => "invalid_configuration",
            Self::MissingAccessToken => "missing_access_token",
            Self::MissingSubject => "missing_subject",
            Self::InvalidIdentityToken => "invalid_identity_token",
            Self::UnsupportedFlow => "unsupported_flow",
            Self::Transport(_) => "transport",
            Self::ProviderRejected(_) => "provider_rejected",
        }
    }
}

pub use github::GithubOauth2Provider;
pub use google::GoogleOauth2Provider;
pub use oauth_like::OAuthLikeProvider;
pub use oidc::OidcProvider;
pub use qq::QqOauth2Provider;
pub use transport::{ProviderTransport, ReqwestProviderTransport};
pub use wechat::WechatOauth2Provider;
