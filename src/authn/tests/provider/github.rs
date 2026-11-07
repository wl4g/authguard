use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::*;
use crate::config::{
    AuthorizationEndpointProperties, IdentityMappingProperties, TokenEndpointProperties,
};
use crate::provider::transport::{IdentityLookupRequest, TokenExchangeRequest};

struct StubTransport;

#[async_trait]
impl ProviderTransport for StubTransport {
    async fn exchange_token(&self, _request: TokenExchangeRequest) -> Result<Value, ProviderError> {
        Ok(json!({"access_token": "github-token"}))
    }

    async fn lookup_identity(
        &self,
        _request: IdentityLookupRequest,
    ) -> Result<Value, ProviderError> {
        Ok(json!({"id": 987_654, "login": "alice", "email": null}))
    }
}

#[tokio::test]
async fn uses_user_api_instead_of_treating_oauth_as_oidc() {
    let adapter = GithubOauth2Provider::new(
        OAuthProviderProperties {
            issuer: "https://github.com".to_string(),
            client_id: String::new(),
            client_secret: String::new(),
            callback_url: String::new(),
            authorization: AuthorizationEndpointProperties {
                endpoint: "https://github.com/login/oauth/authorize".to_string(),
                scopes: vec!["read:user".to_string()],
                query: BTreeMap::new(),
            },
            token: TokenEndpointProperties {
                endpoint: "https://github.com/login/oauth/access_token".to_string(),
                ..TokenEndpointProperties::default()
            },
            identity: IdentityMappingProperties {
                endpoint: Some("https://api.github.com/user".to_string()),
                subject: "$.id".to_string(),
                username: Some("$.login".to_string()),
                email: Some("$.email".to_string()),
                ..IdentityMappingProperties::default()
            },
        },
        StubTransport,
    )
    .expect("GitHub adapter");
    let identity = adapter
        .authenticate(OAuthLikeCallback {
            authorization_code: "code".to_string(),
            redirect_uri: "https://app.example/callback".to_string(),
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            nonce: None,
            pkce_verifier: None,
        })
        .await
        .expect("authenticate");

    assert_eq!(identity.subject, "987654");
    assert_eq!(identity.claims["username"], json!("alice"));
    assert!(!identity.claims.contains_key("email"));
}
