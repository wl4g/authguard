use std::collections::BTreeMap;

use async_trait::async_trait;
use reqwest::{Client, StatusCode, Url};
use serde_json::Value;

use crate::config::CustomPrincipalDiscoveryConfig;
use crate::model::PrincipalKind;
use crate::principal::{
    validate_search_query, CustomRequestBinding, CustomResponseMapping, ExternalPrincipalRef,
    IPrincipalDiscovery, PrincipalDiscoveryError, PrincipalProjection, PrincipalSearchPage,
    PrincipalSearchQuery,
};

const USERS_CURSOR_STREAM: &str = "users";
const GROUPS_CURSOR_STREAM: &str = "groups";

/// One rendered request to a custom in-house identity API.
struct CustomHttpRequest {
    url: Url,
    body: Option<String>,
}

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
    request: CustomRequestBinding,
    response: CustomResponseMapping,
    jwt_token: String,
    max_page_size: u32,
    client: Client,
}

impl CustomPrincipalDiscovery {
    /// Creates a connector from the runtime configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider identifier, URL, JWT, request
    /// binding, response mapping, timeout, or page-size configuration is
    /// invalid.
    pub fn new(config: &CustomPrincipalDiscoveryConfig) -> Result<Self, PrincipalDiscoveryError> {
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
            request: CustomRequestBinding::from(&config.request),
            response: CustomResponseMapping::from(&config.response),
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
            CustomRequestBinding::KIND_PLACEHOLDER => {
                Some(Self::kind_placeholder_value(kind).to_string())
            }
            _ => None,
        });
        let mut url = Self::append_path(&self.base_url, &path)?;
        url.query_pairs_mut()
            .append_pair(&self.request.text_param, query.text.trim())
            .append_pair(&self.request.offset_param, &offset.to_string())
            .append_pair(&self.request.limit_param, &limit.to_string());
        let body = self.request.body_template.as_deref().map(|template| {
            Self::render(template, |placeholder| match placeholder {
                CustomRequestBinding::SEARCH_PLACEHOLDER => Some(query.text.trim().to_string()),
                CustomRequestBinding::OFFSET_PLACEHOLDER => Some(offset.to_string()),
                CustomRequestBinding::LIMIT_PLACEHOLDER => Some(limit.to_string()),
                CustomRequestBinding::KIND_PLACEHOLDER => {
                    Some(Self::kind_placeholder_value(kind).to_string())
                }
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
            CustomRequestBinding::EXTERNAL_ID_PLACEHOLDER => Some(external_id.to_string()),
            CustomRequestBinding::KIND_PLACEHOLDER => {
                Some(Self::kind_placeholder_value(kind).to_string())
            }
            _ => None,
        });
        let mut url = Self::append_path(&self.base_url, &path)?;
        url.query_pairs_mut().append_pair(&self.request.external_id_param, external_id);
        let body = self.request.body_template.as_deref().map(|template| {
            Self::render(template, |placeholder| match placeholder {
                CustomRequestBinding::EXTERNAL_ID_PLACEHOLDER => Some(external_id.to_string()),
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

fn validate_config(config: &CustomPrincipalDiscoveryConfig) -> Result<(), PrincipalDiscoveryError> {
    if config.discovery_id.trim().is_empty()
        || config.discovery_id.trim() != config.discovery_id
        || config.issuer.trim().is_empty()
        || config.issuer.trim() != config.issuer
    {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(
            "custom provider_id and issuer must be non-empty and have no surrounding whitespace"
                .to_string(),
        ));
    }
    if config.jwt_token.trim().is_empty() || config.jwt_token.trim() != config.jwt_token {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(
            "custom jwt_token must be non-empty and have no surrounding whitespace".to_string(),
        ));
    }
    if config.connect_timeout.is_zero() || config.request_timeout.is_zero() {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(
            "custom request timeouts must be positive".to_string(),
        ));
    }
    if !(1..=PrincipalSearchQuery::MAX_PAGE_SIZE).contains(&config.max_page_size) {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(format!(
            "custom max_page_size must be between 1 and {}",
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
                "custom {name} must not be empty"
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
            "custom request.body_template must be valid JSON".to_string(),
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
            "custom request.path must be a non-empty relative path such as `users/search`"
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
            "custom response.array_path must be empty or a JSON pointer such as `/data/items`"
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
            "custom {name} must be non-empty and have no surrounding whitespace"
        )));
    }
    let url = Url::parse(value).map_err(|error| {
        PrincipalDiscoveryError::InvalidConfiguration(format!("invalid custom {name}: {error}"))
    })?;
    if url.host_str().is_none()
        || url.cannot_be_a_base()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(format!(
            "custom {name} must be an absolute hierarchical URL without credentials, query, or fragment"
        )));
    }
    if url.scheme() != "https" && !(url.scheme() == "http" && allow_insecure_http) {
        return Err(PrincipalDiscoveryError::InvalidConfiguration(format!(
            "custom {name} must use HTTPS unless allow_insecure_http is explicitly enabled"
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
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use axum::extract::{Path, Query};
    use axum::http::header::AUTHORIZATION;
    use axum::http::StatusCode as AxumStatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Json, Router};
    use serde_json::json;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::principal::PrincipalSearchQuery;

    struct TestState {
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    async fn start_server() -> (String, TestState, JoinHandle<()>) {
        let state = TestState { calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)) };
        let calls = state.calls.clone();
        let app = Router::new().route(
            "/api/dsp/{kind}/search",
            get(
                move |Query(params): Query<std::collections::HashMap<String, String>>,
                      Path(kind): Path<String>,
                      headers: axum::http::HeaderMap| {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if headers.get(AUTHORIZATION)
                            != Some(&axum::http::HeaderValue::from_static("Bearer dsp-token"))
                        {
                            return (AxumStatusCode::UNAUTHORIZED, Json(json!({}))).into_response();
                        }
                        if let Some(id) = params.get("id") {
                            if id == "missing" {
                                return (AxumStatusCode::NOT_FOUND, Json(json!({})))
                                    .into_response();
                            }
                            return Json(json!({
                                "id": id,
                                "display_name": format!("DSP {id}"),
                                "username": format!("user-{id}"),
                                "email": format!("{id}@example.com"),
                                "enabled": true,
                                "kind": "USER",
                            }))
                            .into_response();
                        }
                        let offset: usize = params.get("offset").unwrap().parse().unwrap();
                        let limit: usize = params.get("limit").unwrap().parse().unwrap();
                        let items = (offset..offset + limit)
                            .map(|i| {
                                json!({
                                    "id": format!("dsp-{i}"),
                                    "display_name": format!("DSP {i}"),
                                    "username": format!("dsp{i}"),
                                    "email": format!("dsp{i}@example.com"),
                                    "enabled": i % 2 == 0,
                                    "kind": kind,
                                })
                            })
                            .collect::<Vec<_>>();
                        Json(json!({ "items": items })).into_response()
                    }
                },
            ),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (address, state, server)
    }

    fn config(url: &str) -> CustomPrincipalDiscoveryConfig {
        use crate::config::{CustomRequestBindingConfig, CustomResponseMappingConfig};
        CustomPrincipalDiscoveryConfig {
            discovery_id: "dsp-directory".to_string(),
            url: url.to_string(),
            issuer: "https://dsp.example.com".to_string(),
            jwt_token: "dsp-token".to_string(),
            request: CustomRequestBindingConfig {
                path: "api/dsp/{{kind}}/search".to_string(),
                text_param: "search".to_string(),
                offset_param: "offset".to_string(),
                limit_param: "limit".to_string(),
                external_id_param: "id".to_string(),
                body_template: None,
            },
            response: CustomResponseMappingConfig {
                array_path: "/items".to_string(),
                id_attr: "id".to_string(),
                display_name_attr: "display_name".to_string(),
                username_attr: Some("username".to_string()),
                email_attr: Some("email".to_string()),
                enabled_attr: Some("enabled".to_string()),
                kind_attr: Some("kind".to_string()),
            },
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(2),
            max_page_size: 100,
            allow_insecure_http: true,
            ..CustomPrincipalDiscoveryConfig::default()
        }
    }

    fn query(text: &str, kinds: &[PrincipalKind]) -> PrincipalSearchQuery {
        PrincipalSearchQuery {
            text: text.to_string(),
            kinds: kinds.iter().copied().collect(),
            provider_ids: std::collections::BTreeSet::new(),
            per_provider_limit: 10,
            cursors: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn render_keeps_unknown_placeholders_and_renders_known_ones() {
        let template = "{\"q\":\"{{search}}\",\"kind\":\"{{kind}}\",\"fixed\":\"{{vendor}}\"}";
        assert_eq!(
            CustomPrincipalDiscovery::render(template, |name| match name {
                CustomRequestBinding::SEARCH_PLACEHOLDER => Some("alice".to_string()),
                CustomRequestBinding::KIND_PLACEHOLDER => Some("user".to_string()),
                _ => None,
            }),
            "{\"q\":\"alice\",\"kind\":\"user\",\"fixed\":\"{{vendor}}\"}"
        );
    }

    #[tokio::test]
    async fn search_maps_kind_aware_entries_and_streams_user_group_cursors() {
        let (address, _state, _server) = start_server().await;
        let discovery = CustomPrincipalDiscovery::new(&config(&address)).unwrap();
        assert_eq!(discovery.provider(), "FED_CUSTOM");

        let page = discovery
            .discover(query("alice", &[PrincipalKind::User, PrincipalKind::Group]))
            .await
            .unwrap();
        // 10 users + 10 groups, both streams returning a full page.
        assert_eq!(page.principals.len(), 20);
        let user = &page.principals[0];
        assert_eq!(user.reference.external_id, "dsp-0");
        assert_eq!(user.reference.issuer, "https://dsp.example.com");
        assert_eq!(user.kind, PrincipalKind::User);
        assert_eq!(user.display_name, "DSP 0");
        assert_eq!(user.username.as_deref(), Some("dsp0"));
        assert_eq!(user.email.as_deref(), Some("dsp0@example.com"));
        assert!(user.enabled);
        let group = &page.principals[10];
        assert_eq!(group.reference.external_id, "group:dsp-0");
        assert_eq!(group.kind, PrincipalKind::Group);
        assert_eq!(page.next_cursors.len(), 2);

        let users_only = discovery.discover(query("alice", &[PrincipalKind::User])).await.unwrap();
        assert_eq!(users_only.principals.len(), 10);
        assert!(users_only.principals.iter().all(|p| p.kind == PrincipalKind::User));
        assert_eq!(users_only.next_cursors.len(), 1);
    }

    #[tokio::test]
    async fn resolve_maps_exact_entry_and_reports_unknown_external_ids() {
        let (address, _state, _server) = start_server().await;
        let discovery = CustomPrincipalDiscovery::new(&config(&address)).unwrap();
        let principal = discovery
            .resolve_principal(&ExternalPrincipalRef {
                provider_id: "dsp-directory".to_string(),
                issuer: "https://dsp.example.com".to_string(),
                external_id: "dsp-7".to_string(),
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(principal.reference.external_id, "dsp-7");
        assert_eq!(principal.display_name, "DSP dsp-7");

        let missing = discovery
            .resolve_principal(&ExternalPrincipalRef {
                provider_id: "dsp-directory".to_string(),
                issuer: "https://dsp.example.com".to_string(),
                external_id: "missing".to_string(),
            })
            .await
            .unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn resolve_requires_configured_jwt_bearer_auth() {
        let (address, state, _server) = start_server().await;
        let discovery = CustomPrincipalDiscovery::new(&config(&address)).unwrap();
        assert!(discovery
            .resolve_principal(&ExternalPrincipalRef {
                provider_id: "dsp-directory".to_string(),
                issuer: "https://dsp.example.com".to_string(),
                external_id: "dsp-0".to_string(),
            })
            .await
            .is_ok());
        assert_eq!(state.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn configuration_rejects_unsafe_or_incomplete_bindings() {
        let base = config("https://dsp.example.com");
        assert!(CustomPrincipalDiscovery::new(&base).is_ok());

        let mut absolute_path = base.clone();
        absolute_path.request.path = "/api/dsp/search".to_string();
        assert!(matches!(
            CustomPrincipalDiscovery::new(&absolute_path),
            Err(PrincipalDiscoveryError::InvalidConfiguration(_))
        ));

        let mut bad_template = base.clone();
        bad_template.request.body_template = Some("not json".to_string());
        assert!(matches!(
            CustomPrincipalDiscovery::new(&bad_template),
            Err(PrincipalDiscoveryError::InvalidConfiguration(_))
        ));

        let mut bad_array = base.clone();
        bad_array.response.array_path = "items".to_string();
        assert!(matches!(
            CustomPrincipalDiscovery::new(&bad_array),
            Err(PrincipalDiscoveryError::InvalidConfiguration(_))
        ));

        let mut empty_token = base;
        empty_token.jwt_token = " ".to_string();
        assert!(matches!(
            CustomPrincipalDiscovery::new(&empty_token),
            Err(PrincipalDiscoveryError::InvalidConfiguration(_))
        ));
    }
}
