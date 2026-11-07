use async_trait::async_trait;

use super::{
    IProviderAdapter, OAuthLikeCallback, OAuthLikeProvider, ProviderError, ProviderTransport,
};
use crate::{config::OAuthProviderProperties, model::ExternalIdentity};

const WECHAT_CLIENT_ID: &str = "appid";
const WECHAT_CLIENT_SECRET: &str = "secret";

pub struct WechatOauth2Provider<T>(OAuthLikeProvider<T>);

impl<T> WechatOauth2Provider<T> {
    /// Creates the `WeChat` adapter.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider configuration is invalid.
    pub fn new(config: OAuthProviderProperties, transport: T) -> Result<Self, ProviderError> {
        OAuthLikeProvider::new("wechat", config, transport).map(Self)
    }
}

#[async_trait]
impl<T: ProviderTransport> IProviderAdapter for WechatOauth2Provider<T> {
    fn provider_id(&self) -> &str {
        self.0.provider_id()
    }

    fn authorization_url(
        &self,
        client_id: &str,
        redirect_uri: &str,
        state: &str,
    ) -> Result<reqwest::Url, ProviderError> {
        let mut url = self.0.authorization_url_with_client_id_parameter(
            client_id,
            redirect_uri,
            state,
            WECHAT_CLIENT_ID,
        )?;
        url.set_fragment(Some("wechat_redirect"));
        Ok(url)
    }

    async fn authenticate(
        &self,
        callback: OAuthLikeCallback,
    ) -> Result<ExternalIdentity, ProviderError> {
        self.0
            .authenticate_with_client_credentials(callback, WECHAT_CLIENT_ID, WECHAT_CLIENT_SECRET)
            .await
    }
}

#[cfg(test)]
#[path = "../../tests/provider/wechat.rs"]
mod tests;
