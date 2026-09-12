use std::collections::BTreeMap;
use std::time::Instant;

use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct KeycloakUser {
    pub(super) id: Option<String>,
    pub(super) username: Option<String>,
    pub(super) first_name: Option<String>,
    pub(super) last_name: Option<String>,
    pub(super) email: Option<String>,
    pub(super) enabled: Option<bool>,
    pub(super) service_account_client_id: Option<String>,
    #[serde(default)]
    pub(super) attributes: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
pub(super) struct KeycloakGroup {
    pub(super) id: Option<String>,
    pub(super) name: Option<String>,
    pub(super) path: Option<String>,
    #[serde(default)]
    pub(super) attributes: BTreeMap<String, Value>,
}

#[derive(Debug)]
pub(super) struct KeycloakEndpoints {
    pub(super) issuer: String,
    pub(super) users: Url,
    pub(super) groups: Url,
    pub(super) token: Url,
}

#[derive(Debug, Deserialize)]
pub(super) struct TokenResponse {
    pub(super) access_token: String,
    pub(super) expires_in: u64,
    pub(super) token_type: String,
}

#[derive(Debug)]
pub(super) struct CachedBearerToken {
    pub(super) value: String,
    pub(super) refresh_at: Instant,
}
