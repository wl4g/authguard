use async_trait::async_trait;

use super::{
    IProviderAdapter, OAuthLikeCallback, OAuthLikeProvider, ProviderError, ProviderTransport,
};
use crate::{config::OAuthProviderProperties, model::ExternalIdentity};

pub struct GoogleOauth2Provider<T>(OAuthLikeProvider<T>);

impl<T> GoogleOauth2Provider<T> {
    /// Creates the Google adapter.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider configuration is invalid.
    pub fn new(config: OAuthProviderProperties, transport: T) -> Result<Self, ProviderError> {
        OAuthLikeProvider::new("google", config, transport).map(Self)
    }
}

#[async_trait]
impl<T: ProviderTransport> IProviderAdapter for GoogleOauth2Provider<T> {
    fn provider_id(&self) -> &str {
        self.0.provider_id()
    }

    fn authorization_url(
        &self,
        client_id: &str,
        redirect_uri: &str,
        state: &str,
    ) -> Result<reqwest::Url, ProviderError> {
        self.0.authorization_url(client_id, redirect_uri, state)
    }

    async fn authenticate(
        &self,
        callback: OAuthLikeCallback,
    ) -> Result<ExternalIdentity, ProviderError> {
        self.0.authenticate(callback).await
    }
}
