use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::{Client, StatusCode, Url};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::config::KeycloakPrincipalDiscoveryConfig;
use crate::model::PrincipalKind;
use crate::principal::{
    validate_search_query, BearerTokenProvider, ExternalPrincipalRef, IPrincipalDiscovery,
    PrincipalDiscoveryError, PrincipalProjection, PrincipalSearchPage, PrincipalSearchQuery,
};

#[derive(Debug)]
struct CachedBearerToken {
    value: String,
    refresh_at: Instant,
}

/// OAuth 2.0 client-credentials token source with an in-process expiry cache.
struct ClientCredentialsBearerTokenProvider {
    provider_id: String,
    client: Client,
    token_endpoint: Url,
    client_id: String,
    client_secret: String,
    cached: Mutex<Option<CachedBearerToken>>,
}

impl ClientCredentialsBearerTokenProvider {
    fn new(
        provider_id: String,
        client: Client,
        token_endpoint: Url,
        client_id: String,
        client_secret: String,
    ) -> Result<Self, PrincipalDiscoveryError> {
        if client_id.trim().is_empty() || client_id.trim() != client_id || client_secret.is_empty()
        {
            return Err(PrincipalDiscoveryError::InvalidConfiguration(
                "Keycloak client_id must be canonical and client_secret must not be empty"
                    .to_string(),
            ));
        }
        Ok(Self {
            provider_id,
            client,
            token_endpoint,
            client_id,
            client_secret,
            cached: Mutex::new(None),
        })
    }

    fn validate_token(
        &self,
        value: String,
        expires_in: u64,
    ) -> Result<CachedBearerToken, PrincipalDiscoveryError> {
        if value.trim().is_empty() || value.trim() != value || expires_in == 0 {
            return Err(PrincipalDiscoveryError::InvalidResponse {
                provider_id: self.provider_id.clone(),
                message: "token response requires a non-empty access_token and expires_in"
                    .to_string(),
            });
        }
        let bounded_expiry = expires_in.min(24 * 60 * 60);
        let refresh_skew = bounded_expiry.min(30);
        let refresh_after = bounded_expiry.saturating_sub(refresh_skew).max(1);
        Ok(CachedBearerToken {
            value,
            refresh_at: Instant::now() + Duration::from_secs(refresh_after),
        })
    }
}

#[async_trait]
impl BearerTokenProvider for ClientCredentialsBearerTokenProvider {
    async fn bearer_token(&self) -> Result<String, PrincipalDiscoveryError> {
        let mut cached = self.cached.lock().await;
        if let Some(token) = cached.as_ref().filter(|token| Instant::now() < token.refresh_at) {
            return Ok(token.value.clone());
        }

        let response = self
            .client
            .post(self.token_endpoint.clone())
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
            ])
            .send()
            .await
            .map_err(|error| transport_error(&self.provider_id, "client_credentials", &error))?;
        if !response.status().is_success() {
            return Err(PrincipalDiscoveryError::Authentication {
                provider_id: self.provider_id.clone(),
            });
        }
        let token: TokenResponse =
            response.json().await.map_err(|_| PrincipalDiscoveryError::InvalidResponse {
                provider_id: self.provider_id.clone(),
                message: "token endpoint returned invalid JSON".to_string(),
            })?;
        if !token.token_type.eq_ignore_ascii_case("bearer") {
            return Err(PrincipalDiscoveryError::InvalidResponse {
                provider_id: self.provider_id.clone(),
                message: "token_type must be Bearer".to_string(),
            });
        }
        let token = self.validate_token(token.access_token, token.expires_in)?;
        let value = token.value.clone();
        cached.replace(token);
        Ok(value)
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    token_type: String,
}

/// Keycloak Admin REST principal provider.
///
/// Arbitrary principal search is a Keycloak Admin REST capability, not an OIDC
/// capability: <https://www.keycloak.org/docs-api/latest/rest-api/index.html>.
/// Keycloak can federate LDAP/AD and custom user stores through User Storage
/// SPI: <https://www.keycloak.org/docs/latest/server_development/#_user-storage-spi>.
/// The LDAP connector boundary follows the LDAP protocol defined by RFC 4511:
/// <https://www.rfc-editor.org/rfc/rfc4511.html>.
pub struct KeycloakPrincipalDiscovery {
    provider_id: String,
    issuer: String,
    users_endpoint: Url,
    groups_endpoint: Url,
    max_page_size: u32,
    client: Client,
    bearer_tokens: Arc<dyn BearerTokenProvider>,
}

impl KeycloakPrincipalDiscovery {
    const USERS_CURSOR_STREAM: &'static str = "users";
    const GROUPS_CURSOR_STREAM: &'static str = "groups";

    /// Creates a provider backed by a deployment-specific bearer-token source.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider identifier, realm, URL, timeout, or
    /// page-size configuration is invalid.
    pub fn with_bearer_provider(
        config: &KeycloakPrincipalDiscoveryConfig,
        bearer_tokens: Arc<dyn BearerTokenProvider>,
    ) -> Result<Self, PrincipalDiscoveryError> {
        let endpoints = KeycloakEndpoints::from_config(config)?;
        let client = build_client(config)?;
        Ok(Self {
            provider_id: config.discovery_id.clone(),
            issuer: endpoints.issuer,
            users_endpoint: endpoints.users,
            groups_endpoint: endpoints.groups,
            max_page_size: config.max_page_size,
            client,
            bearer_tokens,
        })
    }

    /// Creates a provider that obtains and caches its own service-account token.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid provider configuration or empty client
    /// credentials. The secret is used only in the token request and is never
    /// included in provider errors.
    pub fn with_client_credentials(
        config: &KeycloakPrincipalDiscoveryConfig,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Result<Self, PrincipalDiscoveryError> {
        let endpoints = KeycloakEndpoints::from_config(config)?;
        let client = build_client(config)?;
        let bearer_tokens = Arc::new(ClientCredentialsBearerTokenProvider::new(
            config.discovery_id.clone(),
            client.clone(),
            endpoints.token,
            client_id.into(),
            client_secret.into(),
        )?);
        Ok(Self {
            provider_id: config.discovery_id.clone(),
            issuer: endpoints.issuer,
            users_endpoint: endpoints.users,
            groups_endpoint: endpoints.groups,
            max_page_size: config.max_page_size,
            client,
            bearer_tokens,
        })
    }

    async fn token(&self) -> Result<String, PrincipalDiscoveryError> {
        let token = self.bearer_tokens.bearer_token().await?;
        if token.trim().is_empty() || token.trim() != token {
            return Err(PrincipalDiscoveryError::Authentication {
                provider_id: self.provider_id.clone(),
            });
        }
        Ok(token)
    }

    fn map_user(&self, user: KeycloakUser) -> Result<PrincipalProjection, PrincipalDiscoveryError> {
        let external_id = user
            .id
            .filter(|id| !id.trim().is_empty() && id.trim() == id)
            .ok_or_else(|| PrincipalDiscoveryError::InvalidResponse {
                provider_id: self.provider_id.clone(),
                message: "user representation has no canonical id".to_string(),
            })?;
        let kind = if user.service_account_client_id.is_some() {
            PrincipalKind::Workload
        } else {
            PrincipalKind::User
        };
        let display_name = user
            .first_name
            .iter()
            .chain(user.last_name.iter())
            .filter(|part| !part.trim().is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        let display_name = if display_name.is_empty() {
            user.username
                .clone()
                .or_else(|| user.email.clone())
                .unwrap_or_else(|| external_id.clone())
        } else {
            display_name
        };
        Ok(PrincipalProjection {
            reference: ExternalPrincipalRef {
                provider_id: self.provider_id.clone(),
                issuer: self.issuer.clone(),
                external_id,
            },
            kind,
            display_name,
            username: user.username,
            email: user.email,
            enabled: user.enabled.unwrap_or(false),
            attributes: user.attributes,
        })
    }

    fn supports_kind(query: &PrincipalSearchQuery, kind: PrincipalKind) -> bool {
        query.kinds.is_empty() || query.kinds.contains(&kind)
    }

    fn cursor_key(&self, stream: &str) -> String {
        format!("{}:{stream}", self.provider_id)
    }

    fn stream_offset(
        &self,
        query: &PrincipalSearchQuery,
        stream: &str,
    ) -> Result<u32, PrincipalDiscoveryError> {
        let key = self.cursor_key(stream);
        // Accept the former provider-wide cursor as a one-release migration
        // fallback, while always emitting independent stream cursors.
        parse_cursor(query.cursor_for(&key).or_else(|| query.cursor_for(&self.provider_id)), &key)
    }

    fn map_group(
        &self,
        group: KeycloakGroup,
    ) -> Result<PrincipalProjection, PrincipalDiscoveryError> {
        let group_id =
            group.id.filter(|id| !id.trim().is_empty() && id.trim() == id).ok_or_else(|| {
                PrincipalDiscoveryError::InvalidResponse {
                    provider_id: self.provider_id.clone(),
                    message: "group representation has no canonical id".to_string(),
                }
            })?;
        let display_name =
            group.name.filter(|name| !name.trim().is_empty()).unwrap_or_else(|| group_id.clone());
        let mut attributes = group.attributes;
        if let Some(path) = group.path {
            attributes.insert("keycloak.group_path".to_string(), Value::String(path));
        }
        Ok(PrincipalProjection {
            reference: ExternalPrincipalRef {
                provider_id: self.provider_id.clone(),
                issuer: self.issuer.clone(),
                external_id: format!("group:{group_id}"),
            },
            kind: PrincipalKind::Group,
            display_name,
            username: None,
            email: None,
            enabled: true,
            attributes,
        })
    }

    async fn search_groups(
        &self,
        query: &PrincipalSearchQuery,
    ) -> Result<PrincipalSearchPage, PrincipalDiscoveryError> {
        let cursor_key = self.cursor_key(Self::GROUPS_CURSOR_STREAM);
        let offset = self.stream_offset(query, Self::GROUPS_CURSOR_STREAM)?;
        let limit = query.per_provider_limit.min(self.max_page_size);
        let response = self
            .client
            .get(self.groups_endpoint.clone())
            .bearer_auth(self.token().await?)
            .query(&[
                ("search", query.text.trim().to_string()),
                ("first", offset.to_string()),
                ("max", limit.to_string()),
                ("briefRepresentation", "false".to_string()),
            ])
            .send()
            .await
            .map_err(|error| transport_error(&self.provider_id, "search_groups", &error))?;
        ensure_success(&self.provider_id, "search_groups", response.status())?;
        let groups: Vec<KeycloakGroup> =
            response.json().await.map_err(|_| PrincipalDiscoveryError::InvalidResponse {
                provider_id: self.provider_id.clone(),
                message: "group search response is not a valid group array".to_string(),
            })?;
        let has_next = groups.len() == limit as usize;
        let principals =
            groups.into_iter().map(|group| self.map_group(group)).collect::<Result<Vec<_>, _>>()?;
        let next_cursors = if has_next {
            BTreeMap::from([(cursor_key, offset.saturating_add(limit).to_string())])
        } else {
            BTreeMap::new()
        };
        Ok(PrincipalSearchPage { principals, next_cursors })
    }

    async fn search_users(
        &self,
        query: &PrincipalSearchQuery,
    ) -> Result<PrincipalSearchPage, PrincipalDiscoveryError> {
        let cursor_key = self.cursor_key(Self::USERS_CURSOR_STREAM);
        let offset = self.stream_offset(query, Self::USERS_CURSOR_STREAM)?;
        let limit = query.per_provider_limit.min(self.max_page_size);
        let response = self
            .client
            .get(self.users_endpoint.clone())
            .bearer_auth(self.token().await?)
            .query(&[
                ("search", query.text.trim().to_string()),
                ("first", offset.to_string()),
                ("max", limit.to_string()),
                ("briefRepresentation", "false".to_string()),
                ("exact", "false".to_string()),
            ])
            .send()
            .await
            .map_err(|error| transport_error(&self.provider_id, "search_users", &error))?;
        ensure_success(&self.provider_id, "search_users", response.status())?;
        let users: Vec<KeycloakUser> =
            response.json().await.map_err(|_| PrincipalDiscoveryError::InvalidResponse {
                provider_id: self.provider_id.clone(),
                message: "user search response is not a valid user array".to_string(),
            })?;
        let has_next = users.len() == limit as usize;
        let mut principals = Vec::with_capacity(users.len());
        for user in users {
            let principal = self.map_user(user)?;
            if Self::supports_kind(query, principal.kind) {
                principals.push(principal);
            }
        }
        let next_cursors = if has_next {
            BTreeMap::from([(cursor_key, offset.saturating_add(limit).to_string())])
        } else {
            BTreeMap::new()
        };
        Ok(PrincipalSearchPage { principals, next_cursors })
    }
}

#[async_trait]
impl IPrincipalDiscovery<PrincipalSearchQuery> for KeycloakPrincipalDiscovery {
    type Output = PrincipalSearchPage;

    fn provider(&self) -> &'static str {
        "FED_KEYCLOAK"
    }

    async fn discover(
        &self,
        query: PrincipalSearchQuery,
    ) -> Result<Self::Output, PrincipalDiscoveryError> {
        validate_search_query(&query)?;
        if !query.provider_ids.is_empty() && !query.provider_ids.contains(&self.provider_id) {
            return Ok(PrincipalSearchPage::default());
        }
        let search_users = Self::supports_kind(&query, PrincipalKind::User)
            || Self::supports_kind(&query, PrincipalKind::Workload);
        let search_groups = Self::supports_kind(&query, PrincipalKind::Group);
        if !search_users && !search_groups {
            return Ok(PrincipalSearchPage::default());
        }
        match (search_users, search_groups) {
            (true, true) => {
                let (mut users, groups) =
                    tokio::try_join!(self.search_users(&query), self.search_groups(&query))?;
                users.principals.extend(groups.principals);
                users.next_cursors.extend(groups.next_cursors);
                Ok(users)
            }
            (true, false) => self.search_users(&query).await,
            (false, true) => self.search_groups(&query).await,
            (false, false) => Ok(PrincipalSearchPage::default()),
        }
    }

    async fn resolve_principal(
        &self,
        reference: &ExternalPrincipalRef,
    ) -> Result<Option<PrincipalProjection>, PrincipalDiscoveryError> {
        if reference.provider_id != self.provider_id {
            return Err(PrincipalDiscoveryError::UnknownProvider(reference.provider_id.clone()));
        }
        if reference.issuer != self.issuer {
            return Err(PrincipalDiscoveryError::InvalidQuery(
                "principal issuer does not match provider issuer".to_string(),
            ));
        }
        if reference.external_id.trim().is_empty()
            || reference.external_id.trim() != reference.external_id
        {
            return Err(PrincipalDiscoveryError::InvalidQuery(
                "principal external_id must be canonical and non-empty".to_string(),
            ));
        }
        let group_id = reference.external_id.strip_prefix("group:");
        if group_id == Some("") {
            return Err(PrincipalDiscoveryError::InvalidQuery(
                "group external_id must include the provider group id".to_string(),
            ));
        }
        let mut endpoint = if group_id.is_some() {
            self.groups_endpoint.clone()
        } else {
            self.users_endpoint.clone()
        };
        endpoint
            .path_segments_mut()
            .map_err(|()| {
                PrincipalDiscoveryError::InvalidConfiguration(
                    "Keycloak base URL cannot be used as a hierarchical URL".to_string(),
                )
            })?
            .push(group_id.unwrap_or(&reference.external_id));
        let response = self
            .client
            .get(endpoint)
            .bearer_auth(self.token().await?)
            .send()
            .await
            .map_err(|error| transport_error(&self.provider_id, "resolve", &error))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure_success(&self.provider_id, "resolve", response.status())?;
        let principal = if group_id.is_some() {
            let group: KeycloakGroup =
                response.json().await.map_err(|_| PrincipalDiscoveryError::InvalidResponse {
                    provider_id: self.provider_id.clone(),
                    message: "resolve response is not a valid group".to_string(),
                })?;
            self.map_group(group)?
        } else {
            let user: KeycloakUser =
                response.json().await.map_err(|_| PrincipalDiscoveryError::InvalidResponse {
                    provider_id: self.provider_id.clone(),
                    message: "resolve response is not a valid user".to_string(),
                })?;
            self.map_user(user)?
        };
        if principal.reference.external_id != reference.external_id {
            return Err(PrincipalDiscoveryError::InvalidResponse {
                provider_id: self.provider_id.clone(),
                message: "resolved principal external_id does not match request".to_string(),
            });
        }
        Ok(Some(principal))
    }
}

#[derive(Debug)]
struct KeycloakEndpoints {
    issuer: String,
    users: Url,
    groups: Url,
    token: Url,
}

impl KeycloakEndpoints {
    fn from_config(
        config: &KeycloakPrincipalDiscoveryConfig,
    ) -> Result<Self, PrincipalDiscoveryError> {
        validate_config(config)?;
        let base = Url::parse(&config.base_url).map_err(|error| {
            PrincipalDiscoveryError::InvalidConfiguration(format!(
                "invalid Keycloak base_url: {error}"
            ))
        })?;
        let issuer = if config.issuer.is_empty() {
            append_segments(&base, &["realms", config.realm.trim()])?
                .to_string()
                .trim_end_matches('/')
                .to_string()
        } else {
            parse_endpoint("issuer", &config.issuer, config.allow_insecure_http)?;
            config.issuer.clone()
        };
        let users = append_segments(&base, &["admin", "realms", config.realm.trim(), "users"])?;
        let groups = append_segments(&base, &["admin", "realms", config.realm.trim(), "groups"])?;
        let token = append_segments(
            &base,
            &["realms", config.realm.trim(), "protocol", "openid-connect", "token"],
        )?;
        Ok(Self { issuer, users, groups, token })
    }
}

fn validate_config(
    config: &KeycloakPrincipalDiscoveryConfig,
) -> Result<(), PrincipalDiscoveryError> {
    if config.discovery_id.trim().is_empty()
        || config.discovery_id.trim() != config.discovery_id
        || config.realm.trim().is_empty()
        || config.realm.trim() != config.realm
    {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(
            "Keycloak provider_id and realm must be non-empty and have no surrounding whitespace"
                .to_string(),
        ));
    }
    if config.connect_timeout.is_zero() || config.request_timeout.is_zero() {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(
            "Keycloak request timeouts must be positive".to_string(),
        ));
    }
    if !(1..=PrincipalSearchQuery::MAX_PAGE_SIZE).contains(&config.max_page_size) {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(format!(
            "Keycloak max_page_size must be between 1 and {}",
            PrincipalSearchQuery::MAX_PAGE_SIZE
        )));
    }
    parse_endpoint("base_url", &config.base_url, config.allow_insecure_http)?;
    if !config.issuer.is_empty() {
        parse_endpoint("issuer", &config.issuer, config.allow_insecure_http)?;
    }
    Ok(())
}

fn parse_endpoint(
    name: &str,
    value: &str,
    allow_insecure_http: bool,
) -> Result<Url, PrincipalDiscoveryError> {
    if value.is_empty() || value.trim() != value {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(format!(
            "Keycloak {name} must be non-empty and have no surrounding whitespace"
        )));
    }
    let url = Url::parse(value).map_err(|error| {
        PrincipalDiscoveryError::InvalidConfiguration(format!("invalid Keycloak {name}: {error}"))
    })?;
    if url.host_str().is_none()
        || url.cannot_be_a_base()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(
            format!(
                "Keycloak {name} must be an absolute hierarchical URL without credentials, query, or fragment"
            ),
        ));
    }
    if url.scheme() != "https" && !(url.scheme() == "http" && allow_insecure_http) {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(format!(
            "Keycloak {name} must use HTTPS unless allow_insecure_http is explicitly enabled"
        )));
    }
    Ok(url)
}

fn build_client(
    config: &KeycloakPrincipalDiscoveryConfig,
) -> Result<Client, PrincipalDiscoveryError> {
    Client::builder()
        .connect_timeout(config.connect_timeout)
        .timeout(config.request_timeout)
        .user_agent(concat!("authguard/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| {
            PrincipalDiscoveryError::InvalidConfiguration(format!(
                "cannot construct Keycloak HTTP client: {error}"
            ))
        })
}

fn append_segments(base: &Url, segments: &[&str]) -> Result<Url, PrincipalDiscoveryError> {
    let mut url = base.clone();
    let mut path = url.path_segments_mut().map_err(|()| {
        PrincipalDiscoveryError::InvalidConfiguration(
            "Keycloak base_url cannot be used as a hierarchical URL".to_string(),
        )
    })?;
    path.pop_if_empty();
    path.extend(segments);
    drop(path);
    Ok(url)
}

fn parse_cursor(cursor: Option<&str>, provider_id: &str) -> Result<u32, PrincipalDiscoveryError> {
    cursor.map_or(Ok(0), |value| {
        value.parse::<u32>().map_err(|_| {
            PrincipalDiscoveryError::InvalidQuery(format!(
                "cursor for provider `{provider_id}` is invalid"
            ))
        })
    })
}

fn ensure_success(
    provider_id: &str,
    operation: &'static str,
    status: StatusCode,
) -> Result<(), PrincipalDiscoveryError> {
    if status.is_success() {
        return Ok(());
    }
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return Err(PrincipalDiscoveryError::Authentication {
            provider_id: provider_id.to_string(),
        });
    }
    Err(PrincipalDiscoveryError::HttpStatus {
        provider_id: provider_id.to_string(),
        operation,
        status: status.as_u16(),
    })
}

fn transport_error(
    provider_id: &str,
    operation: &'static str,
    error: &reqwest::Error,
) -> PrincipalDiscoveryError {
    let reason = if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connection failed"
    } else {
        "request failed"
    };
    PrincipalDiscoveryError::Transport { provider_id: provider_id.to_string(), operation, reason }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeycloakUser {
    id: Option<String>,
    username: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    enabled: Option<bool>,
    service_account_client_id: Option<String>,
    #[serde(default)]
    attributes: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct KeycloakGroup {
    id: Option<String>,
    name: Option<String>,
    path: Option<String>,
    #[serde(default)]
    attributes: BTreeMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::extract::{Path, Query, State};
    use axum::http::{HeaderMap, StatusCode as AxumStatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use serde_json::{json, Value};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::*;

    struct FixedToken;

    #[async_trait]
    impl BearerTokenProvider for FixedToken {
        async fn bearer_token(&self) -> Result<String, PrincipalDiscoveryError> {
            Ok("admin-token".to_string())
        }
    }

    #[derive(Clone, Default)]
    struct TestState {
        token_requests: Arc<AtomicUsize>,
        user_searches: Arc<AtomicUsize>,
        group_searches: Arc<AtomicUsize>,
    }

    async fn start_server() -> (String, TestState, JoinHandle<()>) {
        let state = TestState::default();
        let app = Router::new()
            .route("/realms/{realm}/protocol/openid-connect/token", post(token))
            .route("/admin/realms/{realm}/users", get(search))
            .route("/admin/realms/{realm}/users/{id}", get(resolve))
            .route("/admin/realms/{realm}/groups", get(search_groups))
            .route("/admin/realms/{realm}/groups/{id}", get(resolve_group))
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test server");
        let address = listener.local_addr().expect("test address");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });
        (format!("http://{address}"), state, handle)
    }

    async fn token(State(state): State<TestState>, Path(realm): Path<String>) -> impl IntoResponse {
        assert_eq!(realm, "customer-growth");
        state.token_requests.fetch_add(1, Ordering::Relaxed);
        Json(json!({
            "access_token": "admin-token",
            "expires_in": 300,
            "token_type": "Bearer"
        }))
    }

    async fn search(
        State(state): State<TestState>,
        Path(realm): Path<String>,
        Query(query): Query<HashMap<String, String>>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        assert_eq!(realm, "customer-growth");
        assert_eq!(
            headers.get("authorization").and_then(|value| value.to_str().ok()),
            Some("Bearer admin-token")
        );
        assert!(query.get("search").is_some_and(|value| !value.is_empty()));
        state.user_searches.fetch_add(1, Ordering::Relaxed);
        assert_eq!(query.get("max").map(String::as_str), Some("2"));
        Json(json!([
            {
                "id": "user-42",
                "username": "alice",
                "firstName": "Alice",
                "lastName": "Analyst",
                "email": "alice@example.com",
                "enabled": true,
                "attributes": {"department": ["growth"]}
            },
            {
                "id": "workload-7",
                "username": "service-account-growth-job",
                "enabled": true,
                "serviceAccountClientId": "growth-job",
                "attributes": {}
            }
        ]))
    }

    async fn resolve(
        Path((_realm, id)): Path<(String, String)>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        assert_eq!(
            headers.get("authorization").and_then(|value| value.to_str().ok()),
            Some("Bearer admin-token")
        );
        if id == "missing" {
            return (AxumStatusCode::NOT_FOUND, Json(Value::Null));
        }
        (
            AxumStatusCode::OK,
            Json(json!({
                "id": id,
                "username": "alice",
                "firstName": "Alice",
                "lastName": "Analyst",
                "enabled": true,
                "attributes": {}
            })),
        )
    }

    async fn search_groups(
        State(state): State<TestState>,
        Path(realm): Path<String>,
        Query(query): Query<HashMap<String, String>>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        assert_eq!(realm, "customer-growth");
        assert_eq!(
            headers.get("authorization").and_then(|value| value.to_str().ok()),
            Some("Bearer admin-token")
        );
        assert!(query.get("search").is_some_and(|value| !value.is_empty()));
        state.group_searches.fetch_add(1, Ordering::Relaxed);
        if query.get("search").map(String::as_str) == Some("mixed-principal") {
            Json(json!([
                {
                    "id": "growth-team-id",
                    "name": "Growth Analytics",
                    "path": "/growth-analytics",
                    "attributes": {"department": ["growth"]}
                },
                {
                    "id": "campaign-team-id",
                    "name": "Campaign Analytics",
                    "path": "/campaign-analytics",
                    "attributes": {"department": ["growth"]}
                }
            ]))
        } else {
            Json(json!([{
                "id": "growth-team-id",
                "name": "Growth Analytics",
                "path": "/growth-analytics",
                "attributes": {"department": ["growth"]}
            }]))
        }
    }

    async fn resolve_group(
        Path((_realm, id)): Path<(String, String)>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        assert_eq!(
            headers.get("authorization").and_then(|value| value.to_str().ok()),
            Some("Bearer admin-token")
        );
        Json(json!({"id": id, "name": "Growth Analytics", "path": "/growth-analytics"}))
    }

    fn test_config(base_url: String) -> KeycloakPrincipalDiscoveryConfig {
        KeycloakPrincipalDiscoveryConfig {
            discovery_id: "corporate-keycloak".to_string(),
            base_url,
            realm: "customer-growth".to_string(),
            allow_insecure_http: true,
            max_page_size: 2,
            ..KeycloakPrincipalDiscoveryConfig::default()
        }
    }

    #[test]
    fn rejects_plain_http_by_default() {
        let config = KeycloakPrincipalDiscoveryConfig {
            discovery_id: "corporate-keycloak".to_string(),
            base_url: "http://id.example.com".to_string(),
            realm: "customer-growth".to_string(),
            ..KeycloakPrincipalDiscoveryConfig::default()
        };
        let result =
            KeycloakPrincipalDiscovery::with_bearer_provider(&config, Arc::new(FixedToken));
        assert!(matches!(result, Err(PrincipalDiscoveryError::InvalidConfiguration(_))));
    }

    #[tokio::test]
    async fn search_maps_users_workloads_and_provider_cursor() {
        let (base_url, _state, server) = start_server().await;
        let expected_issuer = "https://identity.example.com/realms/customer-growth";
        let mut config = test_config(base_url);
        config.issuer = expected_issuer.to_string();
        let provider =
            KeycloakPrincipalDiscovery::with_bearer_provider(&config, Arc::new(FixedToken))
                .expect("provider");
        let mut query = PrincipalSearchQuery::new("alice@example.com");
        query.per_provider_limit = 2;
        query.cursors.insert("corporate-keycloak".to_string(), "20".to_string());
        query.kinds.extend([PrincipalKind::User, PrincipalKind::Workload]);

        let page = provider.discover(query).await.expect("search");

        assert_eq!(page.principals.len(), 2);
        assert_eq!(page.principals[0].kind, PrincipalKind::User);
        assert_eq!(page.principals[0].display_name, "Alice Analyst");
        assert_eq!(page.principals[0].identity_key(), (expected_issuer, "user-42"));
        assert_eq!(page.principals[0].reference.external_id, "user-42");
        assert_eq!(page.principals[1].kind, PrincipalKind::Workload);
        assert_eq!(
            page.next_cursors.get("corporate-keycloak:users").map(String::as_str),
            Some("22")
        );
        server.abort();
    }

    #[tokio::test]
    async fn resolve_returns_principal_or_none() {
        let (base_url, _state, server) = start_server().await;
        let provider = KeycloakPrincipalDiscovery::with_bearer_provider(
            &test_config(base_url),
            Arc::new(FixedToken),
        )
        .expect("provider");
        let existing = ExternalPrincipalRef {
            provider_id: "corporate-keycloak".to_string(),
            issuer: provider.issuer.clone(),
            external_id: "user-42".to_string(),
        };
        let missing =
            ExternalPrincipalRef { external_id: "missing".to_string(), ..existing.clone() };

        assert!(provider.resolve_principal(&existing).await.expect("resolve existing").is_some());
        assert!(provider.resolve_principal(&missing).await.expect("resolve missing").is_none());
        server.abort();
    }

    #[tokio::test]
    async fn resolves_group_reference_using_namespaced_external_id() {
        let (base_url, _state, server) = start_server().await;
        let provider = KeycloakPrincipalDiscovery::with_bearer_provider(
            &test_config(base_url),
            Arc::new(FixedToken),
        )
        .expect("provider");
        let reference = ExternalPrincipalRef {
            provider_id: "corporate-keycloak".to_string(),
            issuer: provider.issuer.clone(),
            external_id: "group:growth-team-id".to_string(),
        };

        let principal =
            provider.resolve_principal(&reference).await.expect("resolve").expect("group");

        assert_eq!(principal.kind, PrincipalKind::Group);
        assert_eq!(principal.reference, reference);
        server.abort();
    }

    #[tokio::test]
    async fn client_credentials_token_is_reused_until_refresh() {
        let (base_url, state, server) = start_server().await;
        let provider = KeycloakPrincipalDiscovery::with_client_credentials(
            &test_config(base_url),
            "authguard-admin",
            "not-logged-secret",
        )
        .expect("provider");
        let mut query = PrincipalSearchQuery::new("alice@example.com");
        query.per_provider_limit = 2;
        query.cursors.insert("corporate-keycloak".to_string(), "20".to_string());
        query.kinds.insert(PrincipalKind::User);

        provider.discover(query.clone()).await.expect("first search");
        provider.discover(query).await.expect("second search");

        assert_eq!(state.token_requests.load(Ordering::Relaxed), 1);
        server.abort();
    }

    #[tokio::test]
    async fn invalid_provider_cursor_fails_before_http_request() {
        let (base_url, state, server) = start_server().await;
        let provider = KeycloakPrincipalDiscovery::with_client_credentials(
            &test_config(base_url),
            "authguard-admin",
            "not-logged-secret",
        )
        .expect("provider");
        let mut query = PrincipalSearchQuery::new("alice@example.com");
        query.cursors.insert("corporate-keycloak".to_string(), "invalid".to_string());

        let result = provider.discover(query).await;

        assert!(matches!(result, Err(PrincipalDiscoveryError::InvalidQuery(_))));
        assert_eq!(state.token_requests.load(Ordering::Relaxed), 0);
        server.abort();
    }

    #[tokio::test]
    async fn group_only_search_does_not_call_the_user_endpoint() {
        let (base_url, state, server) = start_server().await;
        let provider = KeycloakPrincipalDiscovery::with_client_credentials(
            &test_config(base_url),
            "authguard-admin",
            "not-logged-secret",
        )
        .expect("provider");
        let mut query = PrincipalSearchQuery::new("growth-team");
        query.kinds.insert(PrincipalKind::Group);

        let page = provider.discover(query).await.expect("search");

        assert_eq!(page.principals.len(), 1);
        assert_eq!(page.principals[0].kind, PrincipalKind::Group);
        assert_eq!(page.principals[0].reference.external_id, "group:growth-team-id");
        assert_eq!(state.token_requests.load(Ordering::Relaxed), 1);
        assert_eq!(state.user_searches.load(Ordering::Relaxed), 0);
        assert_eq!(state.group_searches.load(Ordering::Relaxed), 1);
        server.abort();
    }

    #[tokio::test]
    async fn default_search_queries_users_and_groups_with_independent_cursors() {
        let (base_url, state, server) = start_server().await;
        let provider = KeycloakPrincipalDiscovery::with_client_credentials(
            &test_config(base_url),
            "authguard-admin",
            "not-logged-secret",
        )
        .expect("provider");
        let mut query = PrincipalSearchQuery::new("mixed-principal");
        query.per_provider_limit = 2;
        query.cursors.insert("corporate-keycloak:users".to_string(), "20".to_string());
        query.cursors.insert("corporate-keycloak:groups".to_string(), "40".to_string());

        let page = provider.discover(query).await.expect("mixed search");

        assert_eq!(page.principals.len(), 4);
        assert_eq!(state.user_searches.load(Ordering::Relaxed), 1);
        assert_eq!(state.group_searches.load(Ordering::Relaxed), 1);
        assert_eq!(state.token_requests.load(Ordering::Relaxed), 1);
        assert_eq!(
            page.next_cursors.get("corporate-keycloak:users").map(String::as_str),
            Some("22")
        );
        assert_eq!(
            page.next_cursors.get("corporate-keycloak:groups").map(String::as_str),
            Some("42")
        );
        server.abort();
    }

    #[tokio::test]
    async fn resolve_rejects_issuer_mismatch_before_requesting_a_token() {
        let (base_url, state, server) = start_server().await;
        let provider = KeycloakPrincipalDiscovery::with_client_credentials(
            &test_config(base_url),
            "authguard-admin",
            "not-logged-secret",
        )
        .expect("provider");
        let reference = ExternalPrincipalRef {
            provider_id: "corporate-keycloak".to_string(),
            issuer: "https://attacker.example/realms/customer-growth".to_string(),
            external_id: "user-42".to_string(),
        };

        let result = provider.resolve_principal(&reference).await;

        assert!(matches!(result, Err(PrincipalDiscoveryError::InvalidQuery(_))));
        assert_eq!(state.token_requests.load(Ordering::Relaxed), 0);
        server.abort();
    }

    #[test]
    fn preserves_explicit_issuer_exactly() {
        let mut config = test_config("http://127.0.0.1:9".to_string());
        let issuer = "https://identity.example.com/realms/customer-growth/";
        config.issuer = issuer.to_string();

        let provider =
            KeycloakPrincipalDiscovery::with_bearer_provider(&config, Arc::new(FixedToken))
                .expect("provider");

        assert_eq!(provider.issuer, issuer);
    }

    #[test]
    fn rejects_configuration_with_surrounding_whitespace() {
        let config = KeycloakPrincipalDiscoveryConfig {
            discovery_id: "corporate-keycloak".to_string(),
            base_url: " https://identity.example.com".to_string(),
            realm: "customer-growth".to_string(),
            ..KeycloakPrincipalDiscoveryConfig::default()
        };

        assert!(matches!(
            KeycloakPrincipalDiscovery::with_bearer_provider(&config, Arc::new(FixedToken)),
            Err(PrincipalDiscoveryError::InvalidConfiguration(_))
        ));
    }

    #[tokio::test]
    async fn oversized_search_text_fails_before_requesting_a_token() {
        let (base_url, state, server) = start_server().await;
        let provider = KeycloakPrincipalDiscovery::with_client_credentials(
            &test_config(base_url),
            "authguard-admin",
            "not-logged-secret",
        )
        .expect("provider");
        let query = PrincipalSearchQuery::new("x".repeat(PrincipalSearchQuery::MAX_TEXT_BYTES + 1));

        let result = provider.discover(query).await;

        assert!(matches!(result, Err(PrincipalDiscoveryError::InvalidQuery(_))));
        assert_eq!(state.token_requests.load(Ordering::Relaxed), 0);
        server.abort();
    }
}
