use std::collections::BTreeMap;

use async_trait::async_trait;
use reqwest::{Client, StatusCode, Url};
use serde_json::Value;

use super::{
    validate_search_query, ExternalPrincipalRef, IPrincipalDiscovery, PrincipalDiscoveryError,
    PrincipalProjection, PrincipalSearchPage, PrincipalSearchQuery,
};
use crate::config::{
    CustomPrincipalDiscoveryProperties, CustomRequestBindingProperties,
    CustomResponseMappingProperties,
};
use crate::model::PrincipalKind;

const USERS_CURSOR_STREAM: &str = "users";
const GROUPS_CURSOR_STREAM: &str = "groups";
const SEARCH_PLACEHOLDER: &str = "search";
const OFFSET_PLACEHOLDER: &str = "offset";
const LIMIT_PLACEHOLDER: &str = "limit";
const KIND_PLACEHOLDER: &str = "kind";
const EXTERNAL_ID_PLACEHOLDER: &str = "external_id";

/// Configurable connector for in-house identity systems such as an enterprise
/// DSP directory.
///
/// There is no RFC for cross-heterogeneous-source identity search, so vendor
/// APIs are integrated per connector. Unlike Keycloak Admin REST or LDAP
/// (RFC 4511), an in-house API has no public protocol to code against; this
/// connector instead maps the vendor request and response schema entirely in
/// configuration and authenticates with a pre-issued bearer JWT, so new
/// systems need no Rust code.
pub struct CustomPrincipalDiscovery {
    provider_id: String,
    issuer: String,
    base_url: Url,
    request: CustomRequestBindingProperties,
    response: CustomResponseMappingProperties,
    jwt_token: String,
    max_page_size: u32,
    client: Client,
}

/// One rendered request to a custom in-house identity API.
struct CustomHttpRequest {
    url: Url,
    body: Option<String>,
}

impl CustomPrincipalDiscovery {
    /// Creates a connector from the runtime configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider identifier, URL, JWT, request
    /// binding, response mapping, timeout, or page-size configuration is
    /// invalid.
    pub fn new(
        config: &CustomPrincipalDiscoveryProperties,
    ) -> Result<Self, PrincipalDiscoveryError> {
        validate_config(config)?;
        let base_url = parse_endpoint("url", &config.url, config.allow_insecure_http)?;
        validate_request_path(&config.request.path)?;
        validate_body_template(config.request.body_template.as_deref())?;
        validate_array_path(&config.response.array_path)?;
        let client = Client::builder()
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .user_agent(concat!("authguard/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| {
                PrincipalDiscoveryError::InvalidConfiguration(format!(
                    "cannot construct custom HTTP client: {error}"
                ))
            })?;
        Ok(Self {
            provider_id: config.discovery_id.clone(),
            issuer: config.issuer.clone(),
            base_url,
            request: config.request.clone(),
            response: config.response.clone(),
            jwt_token: config.jwt_token.clone(),
            max_page_size: config.max_page_size,
            client,
        })
    }

    fn cursor_key(&self, stream: &str) -> String {
        format!("{}:{stream}", self.provider_id)
    }

    fn stream_offset(
        &self,
        query: &PrincipalSearchQuery,
        stream: &str,
    ) -> Result<u32, PrincipalDiscoveryError> {
        query.cursor_for(&self.cursor_key(stream)).map_or(Ok(0), |value| {
            value.parse::<u32>().map_err(|_| {
                PrincipalDiscoveryError::InvalidQuery(format!(
                    "cursor for provider `{}` is invalid",
                    self.provider_id
                ))
            })
        })
    }

    fn supports_kind(query: &PrincipalSearchQuery, kind: PrincipalKind) -> bool {
        query.kinds.is_empty() || query.kinds.contains(&kind)
    }

    /// Appends the configured path and query parameters to the base URL.
    fn search_request(
        &self,
        query: &PrincipalSearchQuery,
        kind: PrincipalKind,
        offset: u32,
        limit: u32,
    ) -> Result<CustomHttpRequest, PrincipalDiscoveryError> {
        let path = Self::render(&self.request.path, |placeholder| match placeholder {
            KIND_PLACEHOLDER => Some(Self::kind_placeholder_value(kind).to_string()),
            _ => None,
        });
        let mut url = Self::append_path(&self.base_url, &path)?;
        url.query_pairs_mut()
            .append_pair(&self.request.text_param, query.text.trim())
            .append_pair(&self.request.offset_param, &offset.to_string())
            .append_pair(&self.request.limit_param, &limit.to_string());
        let body = self.request.body_template.as_deref().map(|template| {
            Self::render(template, |placeholder| match placeholder {
                SEARCH_PLACEHOLDER => Some(query.text.trim().to_string()),
                OFFSET_PLACEHOLDER => Some(offset.to_string()),
                LIMIT_PLACEHOLDER => Some(limit.to_string()),
                KIND_PLACEHOLDER => Some(Self::kind_placeholder_value(kind).to_string()),
                _ => None,
            })
        });
        Ok(CustomHttpRequest { url, body })
    }

    fn resolve_request(
        &self,
        external_id: &str,
        kind: PrincipalKind,
    ) -> Result<CustomHttpRequest, PrincipalDiscoveryError> {
        let path = Self::render(&self.request.path, |placeholder| match placeholder {
            EXTERNAL_ID_PLACEHOLDER => Some(external_id.to_string()),
            KIND_PLACEHOLDER => Some(Self::kind_placeholder_value(kind).to_string()),
            _ => None,
        });
        let mut url = Self::append_path(&self.base_url, &path)?;
        url.query_pairs_mut().append_pair(&self.request.external_id_param, external_id);
        let body = self.request.body_template.as_deref().map(|template| {
            Self::render(template, |placeholder| match placeholder {
                EXTERNAL_ID_PLACEHOLDER => Some(external_id.to_string()),
                _ => None,
            })
        });
        Ok(CustomHttpRequest { url, body })
    }

    fn append_path(base: &Url, path: &str) -> Result<Url, PrincipalDiscoveryError> {
        let mut url = base.clone();
        let mut segments = url.path_segments_mut().map_err(|()| {
            PrincipalDiscoveryError::InvalidConfiguration(
                "custom url cannot be used as a hierarchical URL".to_string(),
            )
        })?;
        segments.pop_if_empty();
        segments.extend(path.split('/').filter(|segment| !segment.is_empty()));
        drop(segments);
        Ok(url)
    }

    fn cursor_stream(kind: PrincipalKind) -> &'static str {
        match kind {
            PrincipalKind::Group => GROUPS_CURSOR_STREAM,
            PrincipalKind::User | PrincipalKind::Workload => USERS_CURSOR_STREAM,
        }
    }

    fn kind_placeholder_value(kind: PrincipalKind) -> &'static str {
        match kind {
            PrincipalKind::Group => "group",
            PrincipalKind::Workload => "workload",
            PrincipalKind::User => "user",
        }
    }

    /// Renders `{{placeholder}}` tokens; unknown placeholders stay literal so
    /// an operator can include vendor literals in the template.
    fn render(template: &str, resolve: impl Fn(&str) -> Option<String>) -> String {
        let mut rendered = String::with_capacity(template.len());
        let mut rest = template;
        while let Some(open) = rest.find("{{") {
            rendered.push_str(&rest[..open]);
            let Some(close) = rest[open..].find("}}").map(|at| open + at) else {
                break;
            };
            match resolve(rest[open + 2..close].trim()) {
                Some(value) => rendered.push_str(&value),
                None => rendered.push_str(&rest[open..close + 2]),
            }
            rest = &rest[close + 2..];
        }
        rendered.push_str(rest);
        rendered
    }

    async fn request_kind(
        &self,
        kind: PrincipalKind,
        query: &PrincipalSearchQuery,
    ) -> Result<PrincipalSearchPage, PrincipalDiscoveryError> {
        let cursor_key = self.cursor_key(Self::cursor_stream(kind));
        let offset = self.stream_offset(query, Self::cursor_stream(kind))?;
        let limit = query.per_provider_limit.min(self.max_page_size);
        let request = self.search_request(query, kind, offset, limit)?;
        let response = self.send(request, "search").await?.json::<Value>().await.map_err(|_| {
            PrincipalDiscoveryError::InvalidResponse {
                provider_id: self.provider_id.clone(),
                message: "custom search response is not valid JSON".to_string(),
            }
        })?;
        let items = select_array(&self.response.array_path, &response).ok_or_else(|| {
            PrincipalDiscoveryError::InvalidResponse {
                provider_id: self.provider_id.clone(),
                message: "custom search response has no array at the configured array_path"
                    .to_string(),
            }
        })?;
        let has_next = items.len() == limit as usize;
        let mut principals = Vec::with_capacity(items.len());
        for item in items {
            let principal = self.map_entry(item, kind)?;
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

    fn request_builder(&self, request: CustomHttpRequest) -> reqwest::RequestBuilder {
        if let Some(body) = request.body {
            self.client
                .post(request.url)
                .bearer_auth(&self.jwt_token)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body)
        } else {
            self.client.get(request.url).bearer_auth(&self.jwt_token)
        }
    }

    async fn send(
        &self,
        request: CustomHttpRequest,
        operation: &'static str,
    ) -> Result<reqwest::Response, PrincipalDiscoveryError> {
        let response = self
            .request_builder(request)
            .send()
            .await
            .map_err(|error| transport_error(&self.provider_id, operation, &error))?;
        ensure_success(&self.provider_id, operation, response.status())?;
        Ok(response)
    }

    fn map_entry(
        &self,
        entry: &Value,
        default_kind: PrincipalKind,
    ) -> Result<PrincipalProjection, PrincipalDiscoveryError> {
        let object = entry.as_object().ok_or_else(|| PrincipalDiscoveryError::InvalidResponse {
            provider_id: self.provider_id.clone(),
            message: "custom search entry is not a JSON object".to_string(),
        })?;
        let external_id = object
            .get(&self.response.id_attr)
            .and_then(Value::as_str)
            .filter(|id| !id.trim().is_empty() && id.trim() == *id)
            .ok_or_else(|| PrincipalDiscoveryError::InvalidResponse {
                provider_id: self.provider_id.clone(),
                message: "custom search entry has no canonical id attribute".to_string(),
            })?;
        let kind = self.response.kind_attr.as_ref().map_or(default_kind, |kind_attr| match object
            .get(kind_attr)
            .and_then(Value::as_str)
        {
            Some("GROUP" | "group" | "Group") => PrincipalKind::Group,
            Some("WORKLOAD" | "workload" | "SERVICE_ACCOUNT" | "service_account") => {
                PrincipalKind::Workload
            }
            _ => PrincipalKind::User,
        });
        let external_id = match kind {
            PrincipalKind::Group => format!("group:{external_id}"),
            PrincipalKind::User | PrincipalKind::Workload => external_id.to_string(),
        };
        let display_name = object
            .get(&self.response.display_name_attr)
            .and_then(Value::as_str)
            .filter(|name| !name.trim().is_empty())
            .map_or_else(|| external_id.clone(), ToString::to_string);
        let enabled = self.response.enabled_attr.as_ref().is_none_or(|enabled_attr| {
            match object.get(enabled_attr) {
                Some(Value::Bool(enabled)) => *enabled,
                Some(Value::String(enabled)) => !enabled.eq_ignore_ascii_case("false"),
                _ => false,
            }
        });
        let attributes = object
            .iter()
            .map(|(name, value)| {
                let normalized = value
                    .as_str()
                    .map_or_else(|| value.clone(), |text| Value::String(text.to_string()));
                (name.clone(), normalized)
            })
            .collect::<BTreeMap<_, _>>();
        Ok(PrincipalProjection {
            reference: ExternalPrincipalRef {
                provider_id: self.provider_id.clone(),
                issuer: self.issuer.clone(),
                external_id,
            },
            kind,
            display_name,
            username: self
                .response
                .username_attr
                .as_ref()
                .and_then(|name| object.get(name).and_then(Value::as_str).map(ToOwned::to_owned)),
            email: self
                .response
                .email_attr
                .as_ref()
                .and_then(|name| object.get(name).and_then(Value::as_str).map(ToOwned::to_owned)),
            enabled,
            attributes,
        })
    }
}

#[async_trait]
impl IPrincipalDiscovery<PrincipalSearchQuery> for CustomPrincipalDiscovery {
    type Output = PrincipalSearchPage;

    fn provider(&self) -> &'static str {
        "FED_CUSTOM"
    }

    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    async fn discover(
        &self,
        query: PrincipalSearchQuery,
    ) -> Result<Self::Output, PrincipalDiscoveryError> {
        validate_search_query(&query)?;
        let search_users = Self::supports_kind(&query, PrincipalKind::User)
            || Self::supports_kind(&query, PrincipalKind::Workload);
        let search_groups = Self::supports_kind(&query, PrincipalKind::Group);
        if !search_users && !search_groups {
            return Ok(PrincipalSearchPage::default());
        }
        let user_kind = if Self::supports_kind(&query, PrincipalKind::Workload) {
            PrincipalKind::Workload
        } else {
            PrincipalKind::User
        };
        match (search_users, search_groups) {
            (true, true) => {
                let (mut users, groups) = tokio::try_join!(
                    self.request_kind(user_kind, &query),
                    self.request_kind(PrincipalKind::Group, &query)
                )?;
                users.principals.extend(groups.principals);
                users.next_cursors.extend(groups.next_cursors);
                Ok(users)
            }
            (true, false) => self.request_kind(user_kind, &query).await,
            (false, true) => self.request_kind(PrincipalKind::Group, &query).await,
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
        let (kind, external_id) = match reference.external_id.strip_prefix("group:") {
            Some(id) if !id.is_empty() => (PrincipalKind::Group, id),
            _ => (PrincipalKind::User, reference.external_id.as_str()),
        };
        let request = self.resolve_request(external_id, kind)?;
        let response = self
            .request_builder(request)
            .send()
            .await
            .map_err(|error| transport_error(&self.provider_id, "resolve", &error))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure_success(&self.provider_id, "resolve", response.status())?;
        let payload = response.json::<Value>().await.map_err(|_| {
            PrincipalDiscoveryError::InvalidResponse {
                provider_id: self.provider_id.clone(),
                message: "custom resolve response is not valid JSON".to_string(),
            }
        })?;
        let entry = payload
            .as_object()
            .and_then(|object| object.get(&self.response.id_attr))
            .is_some()
            .then(|| self.map_entry(&payload, kind))
            .transpose()?;
        let Some(entry) = entry else {
            return Ok(None);
        };
        if entry.reference.external_id != reference.external_id {
            return Err(PrincipalDiscoveryError::InvalidResponse {
                provider_id: self.provider_id.clone(),
                message: "resolved principal external_id does not match request".to_string(),
            });
        }
        Ok(Some(entry))
    }
}

fn validate_config(
    config: &CustomPrincipalDiscoveryProperties,
) -> Result<(), PrincipalDiscoveryError> {
    if config.discovery_id.trim().is_empty()
        || config.discovery_id.trim() != config.discovery_id
        || config.issuer.trim().is_empty()
        || config.issuer.trim() != config.issuer
    {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(
            "HTTP discovery provider_id and issuer must be non-empty and have no surrounding whitespace"
                .to_string(),
        ));
    }
    if config.jwt_token.trim().is_empty() || config.jwt_token.trim() != config.jwt_token {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(
            "HTTP discovery jwt_token must be non-empty and have no surrounding whitespace"
                .to_string(),
        ));
    }
    if config.connect_timeout.is_zero() || config.request_timeout.is_zero() {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(
            "HTTP discovery request timeouts must be positive".to_string(),
        ));
    }
    if !(1..=PrincipalSearchQuery::MAX_PAGE_SIZE).contains(&config.max_page_size) {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(format!(
            "HTTP discovery max_page_size must be between 1 and {}",
            PrincipalSearchQuery::MAX_PAGE_SIZE
        )));
    }
    for (name, value) in [
        ("text_param", &config.request.text_param),
        ("offset_param", &config.request.offset_param),
        ("limit_param", &config.request.limit_param),
        ("external_id_param", &config.request.external_id_param),
        ("id_attr", &config.response.id_attr),
        ("display_name_attr", &config.response.display_name_attr),
    ] {
        if value.trim().is_empty() {
            return Err(PrincipalDiscoveryError::InvalidConfiguration(format!(
                "HTTP discovery {name} must not be empty"
            )));
        }
    }
    Ok(())
}

fn validate_body_template(template: Option<&str>) -> Result<(), PrincipalDiscoveryError> {
    let Some(template) = template else {
        return Ok(());
    };
    if serde_json::from_str::<Value>(template).is_err() {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(
            "HTTP discovery request.body_template must be valid JSON".to_string(),
        ));
    }
    Ok(())
}

/// Validates the request path binding: non-empty, no surrounding whitespace,
/// relative, and free of query or fragment delimiters.
fn validate_request_path(path: &str) -> Result<(), PrincipalDiscoveryError> {
    if path.is_empty()
        || path.trim() != path
        || path.starts_with('/')
        || path.contains('?')
        || path.contains('#')
    {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(
            "HTTP discovery request.path must be a non-empty relative path such as `users/search`"
                .to_string(),
        ));
    }
    Ok(())
}

/// Validates a JSON-pointer-like array path (`/data/items`, empty = payload is
/// the array). <https://www.rfc-editor.org/rfc/rfc6901.html>
fn validate_array_path(path: &str) -> Result<(), PrincipalDiscoveryError> {
    if path.is_empty() {
        return Ok(());
    }
    if !path.starts_with('/') || path.split('/').skip(1).any(str::is_empty) {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(
            "HTTP discovery response.array_path must be empty or a JSON pointer such as `/data/items`"
                .to_string(),
        ));
    }
    Ok(())
}

fn select_array<'a>(path: &str, payload: &'a Value) -> Option<&'a Vec<Value>> {
    if path.is_empty() {
        return payload.as_array();
    }
    let mut current = payload;
    for reference in path.split('/').skip(1) {
        let escaped = reference.replace("~1", "/").replace("~0", "~");
        current = current.as_object()?.get(&escaped)?;
    }
    current.as_array()
}

fn parse_endpoint(
    name: &str,
    value: &str,
    allow_insecure_http: bool,
) -> Result<Url, PrincipalDiscoveryError> {
    if value.is_empty() || value.trim() != value {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(format!(
            "HTTP discovery {name} must be non-empty and have no surrounding whitespace"
        )));
    }
    let url = Url::parse(value).map_err(|error| {
        PrincipalDiscoveryError::InvalidConfiguration(format!(
            "invalid HTTP discovery {name}: {error}"
        ))
    })?;
    if url.host_str().is_none()
        || url.cannot_be_a_base()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(format!(
            "HTTP discovery {name} must be an absolute hierarchical URL without credentials, query, or fragment"
        )));
    }
    if url.scheme() != "https" && !(url.scheme() == "http" && allow_insecure_http) {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(format!(
            "HTTP discovery {name} must use HTTPS unless allow_insecure_http is explicitly enabled"
        )));
    }
    Ok(url)
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

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
