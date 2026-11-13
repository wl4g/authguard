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
    token: Arc<Mutex<Option<TokenExchangeRequest>>>,
    identity: Arc<Mutex<Option<IdentityLookupRequest>>>,
}

#[async_trait]
impl ProviderTransport for StubTransport {
    async fn exchange_token(&self, request: TokenExchangeRequest) -> Result<Value, ProviderError> {
        *self.token.lock().expect("token request") = Some(request);
        Ok(json!({"access_token": "qq-token"}))
    }

    async fn lookup_identity(
        &self,
        request: IdentityLookupRequest,
    ) -> Result<Value, ProviderError> {
        *self.identity.lock().expect("identity request") = Some(request);
        Ok(json!({"client_id": "qq-app", "openid": "qq-user"}))
    }
}

#[tokio::test]
async fn uses_qq_get_exchange_and_query_token_for_openid() {
    let token = Arc::new(Mutex::new(None));
    let identity = Arc::new(Mutex::new(None));
    let adapter = QqOauth2Provider::new(
        OAuthProviderProperties {
            issuer: "https://graph.qq.com".to_string(),
            client_id: String::new(),
            client_secret: String::new(),
            callback_url: String::new(),
            authorization: AuthorizationEndpointProperties {
                endpoint: "https://graph.qq.com/oauth2.0/authorize".to_string(),
                scopes: vec!["get_user_info".to_string(), "get_vip_info".to_string()],
                query: BTreeMap::new(),
            },
            token: TokenEndpointProperties {
                endpoint: "https://graph.qq.com/oauth2.0/token".to_string(),
                method: HttpMethod::Get,
                client_credentials: ClientCredentialPlacement::Query,
                query: BTreeMap::from([("fmt".to_string(), "json".to_string())]),
                ..TokenEndpointProperties::default()
            },
            identity: IdentityMappingProperties {
                endpoint: Some("https://graph.qq.com/oauth2.0/me?fmt=json".to_string()),
                subject: "$.openid".to_string(),
                ..IdentityMappingProperties::default()
            },
        },
        StubTransport { token: token.clone(), identity: identity.clone() },
    )
    .expect("QQ adapter");

    let url = adapter
        .authorization_url("qq-app", "https://app.example/callback", "state")
        .expect("authorization URL");
    assert_eq!(
        url.query_pairs().find(|(name, _)| name == "scope").map(|(_, value)| value.into_owned()),
        Some("get_user_info,get_vip_info".to_string())
    );

    let external = adapter
        .authenticate(OAuthLikeCallback {
            authorization_code: "code".to_string(),
            redirect_uri: "https://app.example/callback".to_string(),
            client_id: "qq-app".to_string(),
            client_secret: "qq-secret".to_string(),
            nonce: None,
            pkce_verifier: None,
        })
        .await
        .expect("QQ identity");

    let token = token.lock().expect("token request").clone().expect("token exchange");
    assert_eq!(token.method, HttpMethod::Get);
    assert_eq!(token.query.get("client_id").map(String::as_str), Some("qq-app"));
    let identity = identity.lock().expect("identity request").clone().expect("OpenID request");
    assert_eq!(identity.access_token_query.as_deref(), Some("access_token"));
    assert_eq!(external.subject, "qq-user");
}
