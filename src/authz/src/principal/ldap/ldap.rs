use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ldap3::controls::{Control, ControlType, MakeCritical, PagedResults};
use ldap3::{ldap_escape, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use reqwest::Url;
use serde_json::Value;

use crate::config::{LdapObjectMappingProperties, LdapPrincipalDiscoveryProperties};
use crate::model::PrincipalKind;
use crate::principal::{
    validate_search_query, ExternalPrincipalRef, IPrincipalDiscovery, PrincipalDiscoveryError,
    PrincipalProjection, PrincipalSearchPage, PrincipalSearchQuery,
};

const USER_CURSOR_STREAM: &str = "users";
const GROUP_CURSOR_STREAM: &str = "groups";

use super::model::{LdapEntry, LdapSearchPage, LdapSearchRequest};

/// RFC 4511 LDAP Principal search and resolution connector.
///
/// The configured bind identity should have only search and attribute-read
/// permission below the configured user and group search bases. Authguard does
/// not require directory write privileges. Bind credentials are retained only
/// by the connector and are never included in errors or logs.
/// <https://www.rfc-editor.org/rfc/rfc4511.html>
pub struct LdapPrincipalDiscovery {
    config: LdapPrincipalDiscoveryProperties,
    client: Arc<dyn ILdapSearchClient>,
}

struct DefaultLdapSearchClient {
    provider_id: String,
    url: String,
    bind_dn: String,
    bind_password: String,
    connect_timeout: Duration,
    request_timeout: Duration,
}

#[async_trait]
trait ILdapSearchClient: Send + Sync + 'static {
    async fn search(
        &self,
        request: LdapSearchRequest,
    ) -> Result<LdapSearchPage, PrincipalDiscoveryError>;
}

impl LdapPrincipalDiscovery {
    /// Creates a validated LDAP discovery source backed by a real LDAP client.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe URLs, malformed filters, invalid DNs or
    /// attributes, empty bind credentials, and unsafe paging limits.
    pub fn new(config: &LdapPrincipalDiscoveryProperties) -> Result<Self, PrincipalDiscoveryError> {
        Self::validate_config(config)?;
        let client = Arc::new(DefaultLdapSearchClient::new(config));
        Ok(Self { config: config.clone(), client })
    }

    #[cfg(test)]
    fn with_client(
        config: &LdapPrincipalDiscoveryProperties,
        client: Arc<dyn ILdapSearchClient>,
    ) -> Result<Self, PrincipalDiscoveryError> {
        Self::validate_config(config)?;
        Ok(Self { config: config.clone(), client })
    }

    fn validate_config(
        config: &LdapPrincipalDiscoveryProperties,
    ) -> Result<(), PrincipalDiscoveryError> {
        Self::validate_canonical("discovery_id", &config.discovery_id)?;
        Self::validate_canonical("issuer", &config.issuer)?;
        Self::validate_dn("base_dn", &config.base_dn, false)?;
        Self::validate_dn("auth.bind_dn", &config.auth.bind_dn, false)?;
        if config.auth.bind_password.is_empty() {
            return Err(Self::configuration_error("auth.bind_password must not be empty"));
        }
        if config.connect_timeout.is_zero() || config.request_timeout.is_zero() {
            return Err(Self::configuration_error("connection timeouts must be positive"));
        }
        if !(1..=PrincipalSearchQuery::MAX_PAGE_SIZE).contains(&config.max_page_size) {
            return Err(Self::configuration_error(format!(
                "max_page_size must be between 1 and {}",
                PrincipalSearchQuery::MAX_PAGE_SIZE
            )));
        }

        let url = Url::parse(&config.url)
            .map_err(|_| Self::configuration_error("url must be an absolute LDAP URL"))?;
        if config.url.trim() != config.url
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Self::configuration_error(
                "url must not contain whitespace, credentials, query, or fragment",
            ));
        }
        match url.scheme() {
            "ldaps" => {}
            "ldap" if config.allow_insecure => {}
            "ldap" => {
                return Err(Self::configuration_error(
                    "url must use LDAPS unless allow_insecure is explicitly enabled",
                ));
            }
            _ => return Err(Self::configuration_error("url scheme must be ldap or ldaps")),
        }
        Url::parse(&config.issuer)
            .map_err(|_| Self::configuration_error("issuer must be an absolute URI"))?;
        Self::validate_mapping("user", &config.user)?;
        Self::validate_mapping("group", &config.group)?;
        Ok(())
    }

    fn validate_mapping(
        kind: &str,
        mapping: &LdapObjectMappingProperties,
    ) -> Result<(), PrincipalDiscoveryError> {
        Self::validate_dn(&format!("{kind}.search_base"), &mapping.search_base, true)?;
        if ldap3::parse_filter(&mapping.object_filter).is_err() {
            return Err(Self::configuration_error(format!(
                "{kind}.object_filter must be a valid RFC 4515 filter"
            )));
        }
        let mut attributes = vec![&mapping.id_attribute, &mapping.name_attribute];
        attributes.extend(mapping.display_name_attribute.iter());
        attributes.extend(mapping.email_attribute.iter());
        attributes.extend(mapping.enabled_attribute.iter());
        attributes.extend(mapping.search_attributes.iter());
        for attribute in attributes {
            Self::validate_attribute(kind, attribute)?;
        }
        if mapping.search_attributes.is_empty() || mapping.search_attributes.len() > 16 {
            return Err(Self::configuration_error(format!(
                "{kind}.search_attributes must contain between 1 and 16 attributes"
            )));
        }
        let unique = mapping
            .search_attributes
            .iter()
            .map(|attribute| attribute.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        if unique.len() != mapping.search_attributes.len() {
            return Err(Self::configuration_error(format!(
                "{kind}.search_attributes must not contain duplicates"
            )));
        }
        Ok(())
    }

    fn validate_attribute(kind: &str, attribute: &str) -> Result<(), PrincipalDiscoveryError> {
        let valid = !attribute.is_empty()
            && attribute.trim() == attribute
            && attribute
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b';'));
        if !valid {
            return Err(Self::configuration_error(format!(
                "{kind} LDAP attribute names must be canonical attribute descriptions"
            )));
        }
        Ok(())
    }

    fn validate_dn(
        name: &str,
        value: &str,
        allow_empty: bool,
    ) -> Result<(), PrincipalDiscoveryError> {
        if (!allow_empty && value.is_empty())
            || value.trim() != value
            || value.contains(['\0', '\r', '\n'])
        {
            return Err(Self::configuration_error(format!(
                "{name} must be a canonical LDAP distinguished name"
            )));
        }
        Ok(())
    }

    fn validate_canonical(name: &str, value: &str) -> Result<(), PrincipalDiscoveryError> {
        if value.is_empty() || value.trim() != value || value.contains(['\0', '\r', '\n']) {
            return Err(Self::configuration_error(format!(
                "{name} must be non-empty and have no surrounding whitespace"
            )));
        }
        Ok(())
    }

    fn configuration_error(message: impl Into<String>) -> PrincipalDiscoveryError {
        PrincipalDiscoveryError::InvalidConfiguration(format!("LDAP {}", message.into()))
    }

    fn cursor_key(&self, stream: &str) -> String {
        PrincipalSearchQuery::cursor_key(&self.config.discovery_id, stream)
    }

    fn decode_cursor(
        &self,
        query: &PrincipalSearchQuery,
        stream: &str,
    ) -> Result<Vec<u8>, PrincipalDiscoveryError> {
        let key = self.cursor_key(stream);
        let cursor = query.cursor_for(&key).or_else(|| query.cursor_for(&self.config.discovery_id));
        cursor.map_or_else(
            || Ok(Vec::new()),
            |value| {
                URL_SAFE_NO_PAD.decode(value).map_err(|_| {
                    PrincipalDiscoveryError::InvalidQuery(format!(
                        "cursor for provider stream {key} is invalid"
                    ))
                })
            },
        )
    }

    fn search_dn(&self, mapping: &LdapObjectMappingProperties) -> String {
        if mapping.search_base.is_empty() {
            self.config.base_dn.clone()
        } else {
            format!("{},{}", mapping.search_base, self.config.base_dn)
        }
    }

    fn mapping(&self, kind: PrincipalKind) -> (&LdapObjectMappingProperties, &'static str) {
        if kind == PrincipalKind::Group {
            (&self.config.group, GROUP_CURSOR_STREAM)
        } else {
            (&self.config.user, USER_CURSOR_STREAM)
        }
    }

    fn requested_attributes(mapping: &LdapObjectMappingProperties) -> Vec<String> {
        let mut attributes =
            BTreeSet::from([mapping.id_attribute.clone(), mapping.name_attribute.clone()]);
        attributes.extend(mapping.search_attributes.iter().cloned());
        attributes.extend(mapping.display_name_attribute.iter().cloned());
        attributes.extend(mapping.email_attribute.iter().cloned());
        attributes.extend(mapping.enabled_attribute.iter().cloned());
        attributes.into_iter().collect()
    }

    fn search_filter(mapping: &LdapObjectMappingProperties, text: &str) -> String {
        let escaped = ldap_escape(text.trim());
        let candidates = mapping.search_attributes.iter().fold(String::new(), |mut out, name| {
            write!(out, "({name}=*{escaped}*)").expect("writing to String cannot fail");
            out
        });
        format!("(&{}(|{candidates}))", mapping.object_filter)
    }

    fn exact_filter(mapping: &LdapObjectMappingProperties, external_id: &str) -> String {
        let escaped = ldap_escape(external_id);
        format!("(&{}({}={escaped}))", mapping.object_filter, mapping.id_attribute)
    }

    fn map_entry(
        &self,
        entry: LdapEntry,
        mapping: &LdapObjectMappingProperties,
        kind: PrincipalKind,
    ) -> Result<PrincipalProjection, PrincipalDiscoveryError> {
        let external_id = self.required_value(&entry, &mapping.id_attribute, "id")?;
        let name = self.required_value(&entry, &mapping.name_attribute, "name")?;
        let display_name = mapping
            .display_name_attribute
            .as_deref()
            .and_then(|attribute| entry.first(attribute))
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(&name)
            .to_string();
        let enabled = mapping.enabled_attribute.as_deref().map_or(Ok(true), |attribute| {
            entry.first(attribute).map_or(Ok(true), |value| self.parse_enabled(value))
        })?;
        let email = mapping
            .email_attribute
            .as_deref()
            .and_then(|attribute| entry.first(attribute))
            .map(ToOwned::to_owned);
        let attributes = entry
            .attributes
            .into_iter()
            .map(|(name, values)| {
                (name, Value::Array(values.into_iter().map(Value::String).collect()))
            })
            .chain(std::iter::once(("ldap.dn".to_string(), Value::String(entry.dn))))
            .collect();
        Ok(PrincipalProjection {
            reference: ExternalPrincipalRef {
                provider_id: self.config.discovery_id.clone(),
                issuer: self.config.issuer.clone(),
                external_id: if kind == PrincipalKind::Group {
                    format!("group:{external_id}")
                } else {
                    external_id
                },
            },
            kind,
            display_name,
            username: (kind == PrincipalKind::User).then_some(name),
            email,
            enabled,
            attributes,
        })
    }

    fn required_value(
        &self,
        entry: &LdapEntry,
        attribute: &str,
        purpose: &str,
    ) -> Result<String, PrincipalDiscoveryError> {
        entry
            .first(attribute)
            .filter(|value| !value.is_empty() && value.trim() == *value)
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                self.invalid_response(format!("entry has no canonical {purpose} attribute"))
            })
    }

    fn parse_enabled(&self, value: &str) -> Result<bool, PrincipalDiscoveryError> {
        match value.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "enabled" | "active" => Ok(true),
            "false" | "0" | "no" | "disabled" | "inactive" => Ok(false),
            _ => Err(self.invalid_response("enabled attribute has an unsupported value")),
        }
    }

    fn invalid_response(&self, message: impl Into<String>) -> PrincipalDiscoveryError {
        PrincipalDiscoveryError::InvalidResponse {
            provider_id: self.config.discovery_id.clone(),
            message: format!("LDAP {}", message.into()),
        }
    }

    async fn search_kind(
        &self,
        query: &PrincipalSearchQuery,
        kind: PrincipalKind,
    ) -> Result<PrincipalSearchPage, PrincipalDiscoveryError> {
        let (mapping, stream) = self.mapping(kind);
        let request = LdapSearchRequest {
            base_dn: self.search_dn(mapping),
            filter: Self::search_filter(mapping, &query.text),
            attributes: Self::requested_attributes(mapping),
            page_size: query.per_provider_limit.min(self.config.max_page_size),
            cookie: self.decode_cursor(query, stream)?,
        };
        let page = self.client.search(request).await?;
        let principals = page
            .entries
            .into_iter()
            .map(|entry| self.map_entry(entry, mapping, kind))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursors = if page.next_cookie.is_empty() {
            BTreeMap::new()
        } else {
            BTreeMap::from([(self.cursor_key(stream), URL_SAFE_NO_PAD.encode(page.next_cookie))])
        };
        Ok(PrincipalSearchPage { principals, next_cursors })
    }

    async fn resolve_kind(
        &self,
        external_id: &str,
        kind: PrincipalKind,
    ) -> Result<Option<PrincipalProjection>, PrincipalDiscoveryError> {
        let (mapping, _) = self.mapping(kind);
        let page = self
            .client
            .search(LdapSearchRequest {
                base_dn: self.search_dn(mapping),
                filter: Self::exact_filter(mapping, external_id),
                attributes: Self::requested_attributes(mapping),
                page_size: 2,
                cookie: Vec::new(),
            })
            .await?;
        match page.entries.len() {
            0 => Ok(None),
            1 => {
                let entry = page.entries.into_iter().next().expect("one entry");
                self.map_entry(entry, mapping, kind).map(Some)
            }
            _ => Err(self.invalid_response("identity attribute is not unique")),
        }
    }
}

#[async_trait]
impl IPrincipalDiscovery<PrincipalSearchQuery> for LdapPrincipalDiscovery {
    type Output = PrincipalSearchPage;

    fn provider(&self) -> &'static str {
        "FED_LDAP"
    }

    fn provider_id(&self) -> &str {
        &self.config.discovery_id
    }

    async fn discover(
        &self,
        query: PrincipalSearchQuery,
    ) -> Result<Self::Output, PrincipalDiscoveryError> {
        validate_search_query(&query)?;
        let users = query.supports_kind(PrincipalKind::User);
        let groups = query.supports_kind(PrincipalKind::Group);
        match (users, groups) {
            (true, true) => {
                let (mut users, groups) = tokio::try_join!(
                    self.search_kind(&query, PrincipalKind::User),
                    self.search_kind(&query, PrincipalKind::Group)
                )?;
                users.principals.extend(groups.principals);
                users.next_cursors.extend(groups.next_cursors);
                Ok(users)
            }
            (true, false) => self.search_kind(&query, PrincipalKind::User).await,
            (false, true) => self.search_kind(&query, PrincipalKind::Group).await,
            (false, false) => Ok(PrincipalSearchPage::default()),
        }
    }

    async fn resolve_principal(
        &self,
        reference: &ExternalPrincipalRef,
    ) -> Result<Option<PrincipalProjection>, PrincipalDiscoveryError> {
        if reference.provider_id != self.config.discovery_id {
            return Err(PrincipalDiscoveryError::UnknownProvider(reference.provider_id.clone()));
        }
        if reference.issuer != self.config.issuer {
            return Err(PrincipalDiscoveryError::InvalidQuery(
                "principal issuer does not match LDAP provider issuer".to_string(),
            ));
        }
        Self::validate_canonical("external_id", &reference.external_id)
            .map_err(|error| PrincipalDiscoveryError::InvalidQuery(error.to_string()))?;
        if let Some(group_id) = reference.external_id.strip_prefix("group:") {
            if group_id.is_empty() {
                return Err(PrincipalDiscoveryError::InvalidQuery(
                    "group external_id must include the directory identity attribute".to_string(),
                ));
            }
            self.resolve_kind(group_id, PrincipalKind::Group).await
        } else {
            self.resolve_kind(&reference.external_id, PrincipalKind::User).await
        }
    }
}

impl DefaultLdapSearchClient {
    fn new(config: &LdapPrincipalDiscoveryProperties) -> Self {
        Self {
            provider_id: config.discovery_id.clone(),
            url: config.url.clone(),
            bind_dn: config.auth.bind_dn.clone(),
            bind_password: config.auth.bind_password.clone(),
            connect_timeout: config.connect_timeout,
            request_timeout: config.request_timeout,
        }
    }

    async fn bound_connection(&self) -> Result<ldap3::Ldap, PrincipalDiscoveryError> {
        let settings = LdapConnSettings::new().set_conn_timeout(self.connect_timeout);
        let (connection, mut ldap) = LdapConnAsync::with_settings(settings, &self.url)
            .await
            .map_err(|error| self.transport_error("connect", &error))?;
        ldap3::drive!(connection);
        let bind = ldap
            .with_timeout(self.request_timeout)
            .simple_bind(&self.bind_dn, &self.bind_password)
            .await
            .and_then(ldap3::LdapResult::success);
        if bind.is_err() {
            let _ = ldap.unbind().await;
            return Err(PrincipalDiscoveryError::Authentication {
                provider_id: self.provider_id.clone(),
            });
        }
        Ok(ldap)
    }

    fn response_cookie(&self, controls: &[Control]) -> Result<Vec<u8>, PrincipalDiscoveryError> {
        let Some(Control(_, raw)) = controls
            .iter()
            .find(|control| matches!(control, Control(Some(ControlType::PagedResults), _)))
        else {
            return Ok(Vec::new());
        };
        catch_unwind(AssertUnwindSafe(|| raw.parse::<PagedResults>().cookie)).map_err(|_| {
            PrincipalDiscoveryError::InvalidResponse {
                provider_id: self.provider_id.clone(),
                message: "LDAP paged-results control is malformed".to_string(),
            }
        })
    }

    fn transport_error(
        &self,
        operation: &'static str,
        error: &ldap3::LdapError,
    ) -> PrincipalDiscoveryError {
        let reason = match error {
            ldap3::LdapError::Timeout { .. } => "timeout",
            ldap3::LdapError::Io { .. } => "connection failed",
            _ => "LDAP operation failed",
        };
        PrincipalDiscoveryError::Transport {
            provider_id: self.provider_id.clone(),
            operation,
            reason,
        }
    }
}

#[async_trait]
impl ILdapSearchClient for DefaultLdapSearchClient {
    async fn search(
        &self,
        request: LdapSearchRequest,
    ) -> Result<LdapSearchPage, PrincipalDiscoveryError> {
        let mut ldap = self.bound_connection().await?;
        let result = ldap
            .with_controls(
                PagedResults {
                    size: i32::try_from(request.page_size).unwrap_or(i32::MAX),
                    cookie: request.cookie,
                }
                .critical(),
            )
            .with_timeout(self.request_timeout)
            .search(&request.base_dn, Scope::Subtree, &request.filter, &request.attributes)
            .await
            .and_then(ldap3::SearchResult::success);
        let _ = ldap.unbind().await;
        let (entries, result) = result.map_err(|error| self.transport_error("search", &error))?;
        let next_cookie = self.response_cookie(&result.ctrls)?;
        let entries = entries
            .into_iter()
            .map(|entry| {
                catch_unwind(AssertUnwindSafe(|| SearchEntry::construct(entry)))
                    .map(LdapEntry::from_search_entry)
                    .map_err(|_| PrincipalDiscoveryError::InvalidResponse {
                        provider_id: self.provider_id.clone(),
                        message: "LDAP search entry is malformed".to_string(),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(LdapSearchPage { entries, next_cookie })
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
