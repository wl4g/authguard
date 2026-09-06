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

use crate::config::{LdapObjectMappingConfig, LdapPrincipalDiscoveryConfig};
use crate::model::PrincipalKind;
use crate::principal::{
    validate_search_query, ExternalPrincipalRef, IPrincipalDiscovery, PrincipalDiscoveryError,
    PrincipalProjection, PrincipalSearchPage, PrincipalSearchQuery,
};

const USER_CURSOR_STREAM: &str = "users";
const GROUP_CURSOR_STREAM: &str = "groups";

#[derive(Clone)]
struct LdapSearchRequest {
    base_dn: String,
    filter: String,
    attributes: Vec<String>,
    page_size: u32,
    cookie: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LdapSearchPage {
    entries: Vec<LdapEntry>,
    next_cookie: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LdapEntry {
    dn: String,
    attributes: BTreeMap<String, Vec<String>>,
}

impl LdapEntry {
    fn from_search_entry(entry: SearchEntry) -> Self {
        let mut attributes = BTreeMap::<String, Vec<String>>::new();
        for (name, values) in entry.attrs {
            attributes.entry(name.to_ascii_lowercase()).or_default().extend(values);
        }
        for (name, values) in entry.bin_attrs {
            attributes
                .entry(name.to_ascii_lowercase())
                .or_default()
                .extend(values.into_iter().map(|value| URL_SAFE_NO_PAD.encode(value)));
        }
        Self { dn: entry.dn, attributes }
    }

    fn first(&self, attribute: &str) -> Option<&str> {
        self.attributes
            .get(&attribute.to_ascii_lowercase())
            .and_then(|values| values.first())
            .map(String::as_str)
    }
}

#[async_trait]
trait ILdapSearchClient: Send + Sync + 'static {
    async fn search(
        &self,
        request: LdapSearchRequest,
    ) -> Result<LdapSearchPage, PrincipalDiscoveryError>;
}

struct DefaultLdapSearchClient {
    provider_id: String,
    url: String,
    bind_dn: String,
    bind_password: String,
    connect_timeout: Duration,
    request_timeout: Duration,
}

impl DefaultLdapSearchClient {
    fn new(config: &LdapPrincipalDiscoveryConfig) -> Self {
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

/// RFC 4511 LDAP Principal search and resolution connector.
///
/// The configured bind identity should have only search and attribute-read
/// permission below the configured user and group search bases. Authguard does
/// not require directory write privileges. Bind credentials are retained only
/// by the connector and are never included in errors or logs.
/// <https://www.rfc-editor.org/rfc/rfc4511.html>
pub struct LdapPrincipalDiscovery {
    config: LdapPrincipalDiscoveryConfig,
    client: Arc<dyn ILdapSearchClient>,
}

impl LdapPrincipalDiscovery {
    /// Creates a validated LDAP discovery source backed by a real LDAP client.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe URLs, malformed filters, invalid DNs or
    /// attributes, empty bind credentials, and unsafe paging limits.
    pub fn new(config: &LdapPrincipalDiscoveryConfig) -> Result<Self, PrincipalDiscoveryError> {
        Self::validate_config(config)?;
        let client = Arc::new(DefaultLdapSearchClient::new(config));
        Ok(Self { config: config.clone(), client })
    }

    #[cfg(test)]
    fn with_client(
        config: &LdapPrincipalDiscoveryConfig,
        client: Arc<dyn ILdapSearchClient>,
    ) -> Result<Self, PrincipalDiscoveryError> {
        Self::validate_config(config)?;
        Ok(Self { config: config.clone(), client })
    }

    fn validate_config(
        config: &LdapPrincipalDiscoveryConfig,
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
        mapping: &LdapObjectMappingConfig,
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

    fn supports_kind(query: &PrincipalSearchQuery, kind: PrincipalKind) -> bool {
        query.kinds.is_empty() || query.kinds.contains(&kind)
    }

    fn cursor_key(&self, stream: &str) -> String {
        format!("{}:{stream}", self.config.discovery_id)
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

    fn search_dn(&self, mapping: &LdapObjectMappingConfig) -> String {
        if mapping.search_base.is_empty() {
            self.config.base_dn.clone()
        } else {
            format!("{},{}", mapping.search_base, self.config.base_dn)
        }
    }

    fn requested_attributes(mapping: &LdapObjectMappingConfig) -> Vec<String> {
        let mut attributes =
            BTreeSet::from([mapping.id_attribute.clone(), mapping.name_attribute.clone()]);
        attributes.extend(mapping.search_attributes.iter().cloned());
        attributes.extend(mapping.display_name_attribute.iter().cloned());
        attributes.extend(mapping.email_attribute.iter().cloned());
        attributes.extend(mapping.enabled_attribute.iter().cloned());
        attributes.into_iter().collect()
    }

    fn search_filter(mapping: &LdapObjectMappingConfig, text: &str) -> String {
        let escaped = ldap_escape(text.trim());
        let mut candidates = String::new();
        for attribute in &mapping.search_attributes {
            let _ = write!(candidates, "({attribute}=*{escaped}*)");
        }
        format!("(&{}(|{candidates}))", mapping.object_filter)
    }

    fn exact_filter(mapping: &LdapObjectMappingConfig, external_id: &str) -> String {
        let escaped = ldap_escape(external_id);
        format!("(&{}({}={escaped}))", mapping.object_filter, mapping.id_attribute)
    }

    fn map_entry(
        &self,
        entry: LdapEntry,
        mapping: &LdapObjectMappingConfig,
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
            .ok_or_else(|| PrincipalDiscoveryError::InvalidResponse {
                provider_id: self.config.discovery_id.clone(),
                message: format!("LDAP entry has no canonical {purpose} attribute"),
            })
    }

    fn parse_enabled(&self, value: &str) -> Result<bool, PrincipalDiscoveryError> {
        match value.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "enabled" | "active" => Ok(true),
            "false" | "0" | "no" | "disabled" | "inactive" => Ok(false),
            _ => Err(PrincipalDiscoveryError::InvalidResponse {
                provider_id: self.config.discovery_id.clone(),
                message: "LDAP enabled attribute has an unsupported value".to_string(),
            }),
        }
    }

    async fn search_kind(
        &self,
        query: &PrincipalSearchQuery,
        mapping: &LdapObjectMappingConfig,
        kind: PrincipalKind,
        stream: &str,
    ) -> Result<PrincipalSearchPage, PrincipalDiscoveryError> {
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
        mapping: &LdapObjectMappingConfig,
        kind: PrincipalKind,
    ) -> Result<Option<PrincipalProjection>, PrincipalDiscoveryError> {
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
            _ => Err(PrincipalDiscoveryError::InvalidResponse {
                provider_id: self.config.discovery_id.clone(),
                message: "LDAP identity attribute is not unique".to_string(),
            }),
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
        let users = Self::supports_kind(&query, PrincipalKind::User);
        let groups = Self::supports_kind(&query, PrincipalKind::Group);
        match (users, groups) {
            (true, true) => {
                let (mut users, groups) = tokio::try_join!(
                    self.search_kind(
                        &query,
                        &self.config.user,
                        PrincipalKind::User,
                        USER_CURSOR_STREAM,
                    ),
                    self.search_kind(
                        &query,
                        &self.config.group,
                        PrincipalKind::Group,
                        GROUP_CURSOR_STREAM,
                    )
                )?;
                users.principals.extend(groups.principals);
                users.next_cursors.extend(groups.next_cursors);
                Ok(users)
            }
            (true, false) => {
                self.search_kind(&query, &self.config.user, PrincipalKind::User, USER_CURSOR_STREAM)
                    .await
            }
            (false, true) => {
                self.search_kind(
                    &query,
                    &self.config.group,
                    PrincipalKind::Group,
                    GROUP_CURSOR_STREAM,
                )
                .await
            }
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
            self.resolve_kind(group_id, &self.config.group, PrincipalKind::Group).await
        } else {
            self.resolve_kind(&reference.external_id, &self.config.user, PrincipalKind::User).await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tokio::sync::Mutex;

    use super::*;
    use crate::config::LdapBindAuthConfig;

    #[derive(Default)]
    struct FakeLdapSearchClient {
        pages: BTreeMap<String, LdapSearchPage>,
        requests: Mutex<Vec<LdapSearchRequest>>,
    }

    impl FakeLdapSearchClient {
        fn with_pages(pages: impl IntoIterator<Item = (String, LdapSearchPage)>) -> Self {
            Self { pages: pages.into_iter().collect(), requests: Mutex::new(Vec::new()) }
        }
    }

    #[async_trait]
    impl ILdapSearchClient for FakeLdapSearchClient {
        async fn search(
            &self,
            request: LdapSearchRequest,
        ) -> Result<LdapSearchPage, PrincipalDiscoveryError> {
            let page = self.pages.get(&request.base_dn).cloned().unwrap_or_default();
            self.requests.lock().await.push(request);
            Ok(page)
        }
    }

    fn user_mapping() -> LdapObjectMappingConfig {
        LdapObjectMappingConfig {
            search_base: "ou=people".to_string(),
            object_filter: "(objectClass=inetOrgPerson)".to_string(),
            id_attribute: "entryUUID".to_string(),
            name_attribute: "uid".to_string(),
            display_name_attribute: Some("cn".to_string()),
            email_attribute: Some("mail".to_string()),
            enabled_attribute: Some("accountEnabled".to_string()),
            search_attributes: ["uid", "cn", "mail"].into_iter().map(str::to_string).collect(),
        }
    }

    fn group_mapping() -> LdapObjectMappingConfig {
        LdapObjectMappingConfig {
            search_base: "ou=groups".to_string(),
            object_filter: "(objectClass=groupOfNames)".to_string(),
            id_attribute: "entryUUID".to_string(),
            name_attribute: "cn".to_string(),
            search_attributes: ["cn"].into_iter().map(str::to_string).collect(),
            ..LdapObjectMappingConfig::default()
        }
    }

    fn config() -> LdapPrincipalDiscoveryConfig {
        LdapPrincipalDiscoveryConfig {
            discovery_id: "corporate-ldap".to_string(),
            url: "ldaps://ldap.example.com:636".to_string(),
            issuer: "https://identity.example.com/directories/corporate".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            auth: LdapBindAuthConfig {
                bind_dn: "uid=authguard,ou=service-accounts,dc=example,dc=com".to_string(),
                bind_password: "not-logged-secret".to_string(),
                ..LdapBindAuthConfig::default()
            },
            user: user_mapping(),
            group: group_mapping(),
            ..LdapPrincipalDiscoveryConfig::default()
        }
    }

    fn user_entry(external_id: &str) -> LdapEntry {
        LdapEntry {
            dn: "uid=alice,ou=people,dc=example,dc=com".to_string(),
            attributes: BTreeMap::from([
                ("entryuuid".to_string(), vec![external_id.to_string()]),
                ("uid".to_string(), vec!["alice".to_string()]),
                ("cn".to_string(), vec!["Alice Analyst".to_string()]),
                ("mail".to_string(), vec!["alice@example.com".to_string()]),
                ("accountenabled".to_string(), vec!["TRUE".to_string()]),
            ]),
        }
    }

    fn group_entry(external_id: &str) -> LdapEntry {
        LdapEntry {
            dn: "cn=growth-analysts,ou=groups,dc=example,dc=com".to_string(),
            attributes: BTreeMap::from([
                ("entryuuid".to_string(), vec![external_id.to_string()]),
                ("cn".to_string(), vec!["growth-analysts".to_string()]),
            ]),
        }
    }

    #[test]
    fn rejects_plain_ldap_by_default_without_exposing_bind_secret() {
        let mut config = config();
        config.url = "ldap://ldap.example.com:389".to_string();

        let error = LdapPrincipalDiscovery::new(&config).err().expect("unsafe LDAP rejected");

        assert!(matches!(error, PrincipalDiscoveryError::InvalidConfiguration(_)));
        assert!(!error.to_string().contains("not-logged-secret"));
    }

    #[test]
    fn accepts_plain_ldap_only_when_explicitly_enabled() {
        let mut config = config();
        config.url = "ldap://127.0.0.1:1389".to_string();
        config.allow_insecure = true;

        assert!(LdapPrincipalDiscovery::new(&config).is_ok());
    }

    #[test]
    fn rejects_malformed_static_filter_and_attribute_description() {
        let mut invalid_filter = config();
        invalid_filter.user.object_filter = "(objectClass=person".to_string();
        assert!(LdapPrincipalDiscovery::new(&invalid_filter).is_err());

        let mut invalid_attribute = config();
        invalid_attribute.user.search_attributes = vec!["uid)(objectClass=*)".to_string()];
        assert!(LdapPrincipalDiscovery::new(&invalid_attribute).is_err());
    }

    #[tokio::test]
    async fn search_maps_user_group_and_independent_paged_cursors() {
        let fake = Arc::new(FakeLdapSearchClient::with_pages([
            (
                "ou=people,dc=example,dc=com".to_string(),
                LdapSearchPage {
                    entries: vec![user_entry("user-42")],
                    next_cookie: b"user-cookie".to_vec(),
                },
            ),
            (
                "ou=groups,dc=example,dc=com".to_string(),
                LdapSearchPage {
                    entries: vec![group_entry("group-7")],
                    next_cookie: b"group-cookie".to_vec(),
                },
            ),
        ]));
        let provider =
            LdapPrincipalDiscovery::with_client(&config(), fake.clone()).expect("provider");

        let page =
            provider.discover(PrincipalSearchQuery::new("growth")).await.expect("search LDAP");

        assert_eq!(page.principals.len(), 2);
        assert_eq!(page.principals[0].kind, PrincipalKind::User);
        assert_eq!(page.principals[0].display_name, "Alice Analyst");
        assert_eq!(page.principals[0].reference.external_id, "user-42");
        assert_eq!(page.principals[1].kind, PrincipalKind::Group);
        assert_eq!(page.principals[1].reference.external_id, "group:group-7");
        assert_eq!(
            page.next_cursors.get("corporate-ldap:users"),
            Some(&URL_SAFE_NO_PAD.encode(b"user-cookie"))
        );
        assert_eq!(
            page.next_cursors.get("corporate-ldap:groups"),
            Some(&URL_SAFE_NO_PAD.encode(b"group-cookie"))
        );
        assert_eq!(fake.requests.lock().await.len(), 2);
    }

    #[tokio::test]
    async fn search_escapes_untrusted_text_before_building_rfc4515_filter() {
        let fake = Arc::new(FakeLdapSearchClient::default());
        let provider =
            LdapPrincipalDiscovery::with_client(&config(), fake.clone()).expect("provider");
        let mut query = PrincipalSearchQuery::new("alice*)(uid=*)");
        query.kinds.insert(PrincipalKind::User);

        provider.discover(query).await.expect("safe search");

        let requests = fake.requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].filter,
            "(&(objectClass=inetOrgPerson)(|(uid=*alice\\2a\\29\\28uid=\\2a\\29*)(cn=*alice\\2a\\29\\28uid=\\2a\\29*)(mail=*alice\\2a\\29\\28uid=\\2a\\29*)))"
        );
        assert!(ldap3::parse_filter(&requests[0].filter).is_ok());
    }

    #[tokio::test]
    async fn kind_selection_prevents_unnecessary_directory_searches() {
        let fake = Arc::new(FakeLdapSearchClient::default());
        let provider =
            LdapPrincipalDiscovery::with_client(&config(), fake.clone()).expect("provider");

        let mut workloads = PrincipalSearchQuery::new("job-runner");
        workloads.kinds.insert(PrincipalKind::Workload);
        assert!(provider.discover(workloads).await.expect("unsupported").principals.is_empty());
        assert!(fake.requests.lock().await.is_empty());
    }

    #[tokio::test]
    async fn cursor_is_decoded_and_page_size_is_bounded_by_provider_configuration() {
        let fake = Arc::new(FakeLdapSearchClient::default());
        let mut provider_config = config();
        provider_config.max_page_size = 10;
        let provider =
            LdapPrincipalDiscovery::with_client(&provider_config, fake.clone()).expect("provider");
        let mut query = PrincipalSearchQuery::new("alice");
        query.kinds.insert(PrincipalKind::User);
        query.per_provider_limit = 80;
        query
            .cursors
            .insert("corporate-ldap:users".to_string(), URL_SAFE_NO_PAD.encode(b"opaque-cookie"));

        provider.discover(query).await.expect("paged search");

        let requests = fake.requests.lock().await;
        assert_eq!(requests[0].cookie, b"opaque-cookie");
        assert_eq!(requests[0].page_size, 10);
    }

    #[tokio::test]
    async fn resolve_uses_exact_escaped_filter_and_stable_issuer_key() {
        let fake = Arc::new(FakeLdapSearchClient::with_pages([(
            "ou=people,dc=example,dc=com".to_string(),
            LdapSearchPage { entries: vec![user_entry("user*)(uid=*)")], next_cookie: Vec::new() },
        )]));
        let provider =
            LdapPrincipalDiscovery::with_client(&config(), fake.clone()).expect("provider");
        let reference = ExternalPrincipalRef {
            provider_id: "corporate-ldap".to_string(),
            issuer: "https://identity.example.com/directories/corporate".to_string(),
            external_id: "user*)(uid=*)".to_string(),
        };

        let projection =
            provider.resolve_principal(&reference).await.expect("resolve").expect("principal");

        assert_eq!(projection.reference, reference);
        let requests = fake.requests.lock().await;
        assert_eq!(
            requests[0].filter,
            "(&(objectClass=inetOrgPerson)(entryUUID=user\\2a\\29\\28uid=\\2a\\29))"
        );
        assert!(ldap3::parse_filter(&requests[0].filter).is_ok());
    }

    #[tokio::test]
    async fn resolve_rejects_non_unique_identity_attribute() {
        let fake = Arc::new(FakeLdapSearchClient::with_pages([(
            "ou=people,dc=example,dc=com".to_string(),
            LdapSearchPage {
                entries: vec![user_entry("duplicate"), user_entry("duplicate")],
                next_cookie: Vec::new(),
            },
        )]));
        let provider = LdapPrincipalDiscovery::with_client(&config(), fake).expect("provider");
        let reference = ExternalPrincipalRef {
            provider_id: "corporate-ldap".to_string(),
            issuer: "https://identity.example.com/directories/corporate".to_string(),
            external_id: "duplicate".to_string(),
        };

        let result = provider.resolve_principal(&reference).await;

        assert!(matches!(result, Err(PrincipalDiscoveryError::InvalidResponse { .. })));
    }

    #[tokio::test]
    async fn resolve_rejects_provider_and_issuer_mismatch_before_directory_access() {
        let fake = Arc::new(FakeLdapSearchClient::default());
        let provider =
            LdapPrincipalDiscovery::with_client(&config(), fake.clone()).expect("provider");
        let wrong_provider = ExternalPrincipalRef {
            provider_id: "other-ldap".to_string(),
            issuer: "https://identity.example.com/directories/corporate".to_string(),
            external_id: "user-42".to_string(),
        };
        let wrong_issuer = ExternalPrincipalRef {
            provider_id: "corporate-ldap".to_string(),
            issuer: "https://attacker.example/directories/corporate".to_string(),
            external_id: "user-42".to_string(),
        };

        assert!(matches!(
            provider.resolve_principal(&wrong_provider).await,
            Err(PrincipalDiscoveryError::UnknownProvider(_))
        ));
        assert!(matches!(
            provider.resolve_principal(&wrong_issuer).await,
            Err(PrincipalDiscoveryError::InvalidQuery(_))
        ));
        assert!(fake.requests.lock().await.is_empty());
    }

    #[tokio::test]
    async fn unsupported_enabled_value_fails_closed() {
        let mut entry = user_entry("user-42");
        entry.attributes.insert("accountenabled".to_string(), vec!["perhaps".to_string()]);
        let fake = Arc::new(FakeLdapSearchClient::with_pages([(
            "ou=people,dc=example,dc=com".to_string(),
            LdapSearchPage { entries: vec![entry], next_cookie: Vec::new() },
        )]));
        let provider = LdapPrincipalDiscovery::with_client(&config(), fake).expect("provider");
        let mut query = PrincipalSearchQuery::new("alice");
        query.kinds.insert(PrincipalKind::User);

        let result = provider.discover(query).await;

        assert!(matches!(result, Err(PrincipalDiscoveryError::InvalidResponse { .. })));
    }
}
