use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::{Client, StatusCode, Url};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::config::KeycloakPrincipalDiscoveryProperties;
use crate::model::PrincipalKind;
use crate::principal::{
    validate_search_query, BearerTokenProvider, ExternalPrincipalRef, IPrincipalDiscovery,
    PrincipalDiscoveryError, PrincipalProjection, PrincipalSearchPage, PrincipalSearchQuery,
};

use super::model::{
    CachedBearerToken, KeycloakEndpoints, KeycloakGroup, KeycloakUser, TokenResponse,
};

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

/// OAuth 2.0 client-credentials source with an in-process expiry cache.
struct ClientCredentialsBearerTokenProvider {
    provider_id: String,
    client: Client,
    token_endpoint: Url,
    client_id: String,
    client_secret: String,
    cached: Mutex<Option<CachedBearerToken>>,
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
        config: &KeycloakPrincipalDiscoveryProperties,
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
        config: &KeycloakPrincipalDiscoveryProperties,
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
        // Keycloak's collection representation may omit
        // `serviceAccountClientId` even with `briefRepresentation=false`.
        // Its reserved service-account username remains
        // `service-account-{clientId}`, so retain that provider-defined
        // fallback instead of silently materializing a machine as a USER.
        let is_service_account = user
            .service_account_client_id
            .as_deref()
            .is_some_and(|client_id| !client_id.trim().is_empty())
            || user
                .username
                .as_deref()
                .and_then(|username| username.strip_prefix("service-account-"))
                .is_some_and(|client_id| !client_id.is_empty());
        let kind = if is_service_account { PrincipalKind::Workload } else { PrincipalKind::User };
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

    fn cursor_key(&self, stream: &str) -> String {
        PrincipalSearchQuery::cursor_key(&self.provider_id, stream)
    }

    fn stream_offset(
        &self,
        query: &PrincipalSearchQuery,
        stream: &str,
    ) -> Result<u32, PrincipalDiscoveryError> {
        query.offset_cursor(&self.provider_id, stream)
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
        let workload_only = query.supports_kind(PrincipalKind::Workload)
            && !query.supports_kind(PrincipalKind::User);
        let mut request =
            self.client.get(self.users_endpoint.clone()).bearer_auth(self.token().await?).query(&[
                ("first", offset.to_string()),
                ("max", limit.to_string()),
                ("briefRepresentation", "false".to_string()),
            ]);
        // Keycloak's broad `search` path can omit service-account users.
        // A workload-only lookup has a provider-defined exact username, so use
        // the dedicated username filter while keeping broad user searches for
        // interactive identities.
        request = if workload_only {
            request.query(&[
                ("username", query.text.trim().to_string()),
                ("exact", "true".to_string()),
            ])
        } else {
            request
                .query(&[("search", query.text.trim().to_string()), ("exact", "false".to_string())])
        };
        let response = request
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
            if query.supports_kind(principal.kind) {
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

    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    async fn discover(
        &self,
        query: PrincipalSearchQuery,
    ) -> Result<Self::Output, PrincipalDiscoveryError> {
        validate_search_query(&query)?;
        let search_users = query.supports_kind(PrincipalKind::User)
            || query.supports_kind(PrincipalKind::Workload);
        let search_groups = query.supports_kind(PrincipalKind::Group);
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

impl KeycloakEndpoints {
    fn from_config(
        config: &KeycloakPrincipalDiscoveryProperties,
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
            config.issuer.clone()
        };
        let users = append_segments(&base, &["admin", "realms", config.realm.trim(), "users"])?;
        let groups = append_segments(&base, &["admin", "realms", config.realm.trim(), "groups"])?;
        let token = if config.auth.token_url.is_empty() {
            append_segments(
                &base,
                &["realms", config.realm.trim(), "protocol", "openid-connect", "token"],
            )?
        } else {
            parse_endpoint("auth.token_url", &config.auth.token_url, config.allow_insecure_http)?
        };
        Ok(Self { issuer, users, groups, token })
    }
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

    fn cache_token(
        &self,
        response: TokenResponse,
    ) -> Result<CachedBearerToken, PrincipalDiscoveryError> {
        if !response.token_type.eq_ignore_ascii_case("bearer")
            || response.access_token.trim().is_empty()
            || response.access_token.trim() != response.access_token
            || response.expires_in == 0
        {
            return Err(PrincipalDiscoveryError::InvalidResponse {
                provider_id: self.provider_id.clone(),
                message: "token response requires a Bearer access_token and positive expires_in"
                    .to_string(),
            });
        }
        let expiry = response.expires_in.min(24 * 60 * 60);
        Ok(CachedBearerToken {
            value: response.access_token,
            refresh_at: Instant::now()
                + Duration::from_secs(expiry.saturating_sub(expiry.min(30)).max(1)),
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
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
            ])
            .send()
            .await
            .map_err(|error| transport_error(&self.provider_id, "client_credentials", &error))?;
        if !response.status().is_success() {
            return Err(PrincipalDiscoveryError::Authentication {
                provider_id: self.provider_id.clone(),
            });
        }
        let token = self.cache_token(response.json::<TokenResponse>().await.map_err(|_| {
            PrincipalDiscoveryError::InvalidResponse {
                provider_id: self.provider_id.clone(),
                message: "token endpoint returned invalid JSON".to_string(),
            }
        })?)?;
        let value = token.value.clone();
        cached.replace(token);
        Ok(value)
    }
}

fn build_client(
    config: &KeycloakPrincipalDiscoveryProperties,
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

fn ensure_success(
    provider_id: &str,
    operation: &'static str,
    status: StatusCode,
) -> Result<(), PrincipalDiscoveryError> {
    if status.is_success() {
        Ok(())
    } else if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        Err(PrincipalDiscoveryError::Authentication { provider_id: provider_id.into() })
    } else {
        Err(PrincipalDiscoveryError::HttpStatus {
            provider_id: provider_id.into(),
            operation,
            status: status.as_u16(),
        })
    }
}

fn transport_error(
    provider_id: &str,
    operation: &'static str,
    error: &reqwest::Error,
) -> PrincipalDiscoveryError {
    PrincipalDiscoveryError::Transport {
        provider_id: provider_id.into(),
        operation,
        reason: if error.is_timeout() {
            "timeout"
        } else if error.is_connect() {
            "connection failed"
        } else {
            "request failed"
        },
    }
}

fn validate_config(
    config: &KeycloakPrincipalDiscoveryProperties,
) -> Result<(), PrincipalDiscoveryError> {
    if [config.discovery_id.as_str(), config.realm.as_str()]
        .into_iter()
        .any(|value| value.trim().is_empty() || value.trim() != value)
    {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(
            "Keycloak provider_id and realm must be canonical".into(),
        ));
    }
    if config.connect_timeout.is_zero() || config.request_timeout.is_zero() {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(
            "Keycloak request timeouts must be positive".into(),
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
    let url = Url::parse(value).map_err(|error| {
        PrincipalDiscoveryError::InvalidConfiguration(format!("invalid Keycloak {name}: {error}"))
    })?;
    if value.is_empty()
        || value.trim() != value
        || url.host_str().is_none()
        || url.cannot_be_a_base()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || (url.scheme() != "https" && !(url.scheme() == "http" && allow_insecure_http))
    {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(format!(
            "Keycloak {name} must be a canonical HTTPS hierarchical URL without credentials, query, or fragment"
        )));
    }
    Ok(url)
}

fn append_segments(base: &Url, segments: &[&str]) -> Result<Url, PrincipalDiscoveryError> {
    let mut url = base.clone();
    let mut path = url.path_segments_mut().map_err(|()| {
        PrincipalDiscoveryError::InvalidConfiguration(
            "Keycloak base_url must be hierarchical".into(),
        )
    })?;
    path.pop_if_empty();
    path.extend(segments);
    drop(path);
    Ok(url)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
