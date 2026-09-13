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
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use serde_json::{json, Value};

    use super::*;
    use crate::config::{
        AuthorizationEndpointProperties, ClientCredentialPlacement, HttpMethod,
        IdentityMappingProperties, TokenEndpointProperties,
    };
    use crate::provider::transport::{IdentityLookupRequest, TokenExchangeRequest};

    struct StubTransport {
        exchange: Arc<Mutex<Option<TokenExchangeRequest>>>,
    }

    #[async_trait]
    impl ProviderTransport for StubTransport {
        async fn exchange_token(
            &self,
            request: TokenExchangeRequest,
        ) -> Result<Value, ProviderError> {
            *self.exchange.lock().expect("exchange lock") = Some(request);
            Ok(json!({"access_token": "wechat-token", "openid": "wx-user"}))
        }

        async fn lookup_identity(
            &self,
            _request: IdentityLookupRequest,
        ) -> Result<Value, ProviderError> {
            unreachable!("identity endpoint is not configured")
        }
    }

    fn provider(
        exchange: Arc<Mutex<Option<TokenExchangeRequest>>>,
    ) -> WechatOauth2Provider<StubTransport> {
        WechatOauth2Provider::new(
            OAuthProviderProperties {
                issuer: "https://open.weixin.qq.com".to_string(),
                client_id: String::new(),
                client_secret: String::new(),
                callback_url: String::new(),
                authorization: AuthorizationEndpointProperties {
                    endpoint: "https://open.weixin.qq.com/connect/qrconnect".to_string(),
                    scopes: vec!["snsapi_login".to_string()],
                    query: BTreeMap::new(),
                },
                token: TokenEndpointProperties {
                    endpoint: "https://api.weixin.qq.com/sns/oauth2/access_token".to_string(),
                    method: HttpMethod::Get,
                    client_credentials: ClientCredentialPlacement::Query,
                    ..TokenEndpointProperties::default()
                },
                identity: IdentityMappingProperties {
                    subject: "$.unionid".to_string(),
                    fallback_subject: Some("$.openid".to_string()),
                    ..IdentityMappingProperties::default()
                },
            },
            StubTransport { exchange },
        )
        .expect("WeChat adapter")
    }

    #[tokio::test]
    async fn overrides_wechat_client_parameter_names() {
        let exchange = Arc::new(Mutex::new(None));
        let adapter = provider(exchange.clone());
        let url = adapter
            .authorization_url("wx-app-id", "https://app.example/callback", "state")
            .expect("authorization URL");
        let query = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
        assert_eq!(query.get("appid").map(String::as_str), Some("wx-app-id"));
        assert!(!query.contains_key("client_id"));
        assert_eq!(url.fragment(), Some("wechat_redirect"));

        let identity = adapter
            .authenticate(OAuthLikeCallback {
                authorization_code: "code".to_string(),
                redirect_uri: "https://app.example/callback".to_string(),
                client_id: "wx-app-id".to_string(),
                client_secret: "wx-secret".to_string(),
                nonce: None,
                pkce_verifier: None,
            })
            .await
            .expect("authenticate");
        let request = exchange.lock().expect("exchange lock").clone().expect("token request");
        assert_eq!(request.query.get("appid").map(String::as_str), Some("wx-app-id"));
        assert_eq!(request.query.get("secret").map(String::as_str), Some("wx-secret"));
        assert_eq!(identity.subject, "wx-user");
    }
}
