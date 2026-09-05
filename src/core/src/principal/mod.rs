//! Protocol-neutral Principal discovery and projection.
//!
//! Authguard stores a compact projection of identities owned by an external
//! identity provider. For OIDC identities, `(issuer, external_id)` is the
//! stable key: `OpenID` Connect defines `iss` + `sub` as the only locally unique
//! and never-reassigned identifier pair.
//! <https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability>

mod federation;
mod jit;
mod scim;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::handler::PrincipalHandler;

pub use crate::model::PrincipalKind;
pub use federation::{
    CustomPrincipalDiscovery, KeycloakPrincipalDiscovery, LdapPrincipalDiscovery,
};
pub use jit::{JitPrincipalDiscovery, PrincipalProjectionError};
pub use scim::{
    ScimGroupResource, ScimPrincipalDiscovery, ScimProjectionEvent, ScimRefreshRequest,
    ScimUserResource,
};

/// Stable reference to one Principal in one configured identity provider.
///
/// The `(issuer, external_id)` pair is the external identity key. For an OIDC
/// Principal, the values are the verified `iss` and `sub` claims respectively.
/// <https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ExternalPrincipalRef {
    pub provider_id: String,
    pub issuer: String,
    pub external_id: String,
}

/// Protocol-neutral projection returned by a discovery implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalProjection {
    pub reference: ExternalPrincipalRef,
    pub kind: PrincipalKind,
    pub display_name: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, Value>,
}

impl PrincipalProjection {
    #[must_use]
    pub fn identity_key(&self) -> (&str, &str) {
        (&self.reference.issuer, &self.reference.external_id)
    }
}

/// Bounded, provider-neutral Principal search request.
///
/// Cursors are opaque. A cursor is scoped to its named provider so a
/// federated search can advance providers independently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalSearchQuery {
    pub text: String,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub kinds: BTreeSet<PrincipalKind>,
    /// Provider protocol identifiers such as `FED_KEYCLOAK`, `FED_LDAP`, or
    /// `FED_CUSTOM`. When empty, all configured providers are searched.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub provider_ids: BTreeSet<String>,
    pub per_provider_limit: u32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cursors: BTreeMap<String, String>,
}

impl PrincipalSearchQuery {
    pub const DEFAULT_PAGE_SIZE: u32 = 20;
    pub const MAX_PAGE_SIZE: u32 = 100;
    pub const MAX_TEXT_BYTES: usize = 256;

    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            kinds: BTreeSet::new(),
            provider_ids: BTreeSet::new(),
            per_provider_limit: Self::DEFAULT_PAGE_SIZE,
            cursors: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn cursor_for(&self, provider_id: &str) -> Option<&str> {
        self.cursors.get(provider_id).map(String::as_str)
    }
}

/// One federated search page, including one opaque cursor per provider.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalSearchPage {
    pub principals: Vec<PrincipalProjection>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub next_cursors: BTreeMap<String, String>,
}

/// Validates the shared search-request bounds before any provider I/O.
///
/// Every federated provider enforces the same text and page-size limits, so
/// the check is defined once next to the query type.
pub(crate) fn validate_search_query(
    query: &PrincipalSearchQuery,
) -> Result<(), PrincipalDiscoveryError> {
    if query.text.trim().is_empty() {
        return Err(PrincipalDiscoveryError::InvalidQuery(
            "search text must not be empty".to_string(),
        ));
    }
    if query.text.len() > PrincipalSearchQuery::MAX_TEXT_BYTES {
        return Err(PrincipalDiscoveryError::InvalidQuery(format!(
            "search text must not exceed {} bytes",
            PrincipalSearchQuery::MAX_TEXT_BYTES
        )));
    }
    if !(1..=PrincipalSearchQuery::MAX_PAGE_SIZE).contains(&query.per_provider_limit) {
        return Err(PrincipalDiscoveryError::InvalidQuery(format!(
            "per_provider_limit must be between 1 and {}",
            PrincipalSearchQuery::MAX_PAGE_SIZE
        )));
    }
    Ok(())
}

/// Principal claims supplied only after an upstream OIDC verifier has
/// authenticated the token and validated issuer, audience, and lifetime.
///
/// `OpenID` Connect Core: <https://openid.net/specs/openid-connect-core-1_0.html>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOidcPrincipal {
    pub issuer: String,
    pub subject: String,
    pub kind: PrincipalKind,
    pub display_name: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub enabled: bool,
    pub attributes: BTreeMap<String, Value>,
}

impl VerifiedOidcPrincipal {
    #[must_use]
    pub fn user(issuer: impl Into<String>, subject: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            subject: subject.into(),
            kind: PrincipalKind::User,
            display_name: None,
            username: None,
            email: None,
            enabled: true,
            attributes: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum PrincipalDiscoveryError {
    #[error("invalid Principal discovery configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid principal search query: {0}")]
    InvalidQuery(String),
    #[error("unknown Principal discovery source `{0}`")]
    UnknownProvider(String),
    #[error("principal provider `{provider_id}` authentication failed")]
    Authentication { provider_id: String },
    #[error("principal provider `{provider_id}` operation `{operation}` returned HTTP {status}")]
    HttpStatus { provider_id: String, operation: &'static str, status: u16 },
    #[error("principal provider `{provider_id}` operation `{operation}` failed: {reason}")]
    Transport { provider_id: String, operation: &'static str, reason: &'static str },
    #[error("principal provider `{provider_id}` returned an invalid response: {message}")]
    InvalidResponse { provider_id: String, message: String },
    #[error("principal provider task failed: {0}")]
    Task(String),
}

/// Broad, protocol-neutral discovery contract with a strongly typed input.
///
/// JIT projection, federated search, and SCIM synchronization share this
/// contract without being forced into one operation-specific interface.
///
/// A search-capable implementation (Keycloak Admin REST, LDAP per RFC 4511,
/// cloud IAM, or a custom enterprise identity API) re-resolves a selected
/// search result through [`IPrincipalDiscovery::resolve_principal`] so the
/// management API never trusts client-supplied candidate data.
/// <https://www.rfc-editor.org/rfc/rfc4511.html>
#[async_trait]
pub trait IPrincipalDiscovery<Input>: Send + Sync + 'static
where
    Input: Send + 'static,
{
    type Output: Send + 'static;

    /// Identifies the discovery provider protocol.
    ///
    /// Federated search connectors return `FED_KEYCLOAK`, `FED_LDAP`, or
    /// `FED_CUSTOM`; the JIT projection returns `JIT` and SCIM
    /// synchronization returns `SCIM`.
    fn provider(&self) -> &'static str;

    /// Executes one discovery operation.
    ///
    /// # Errors
    ///
    /// Returns validation, authentication, transport, or protocol errors.
    async fn discover(&self, input: Input) -> Result<Self::Output, PrincipalDiscoveryError>;

    /// Re-resolves one stable external Principal reference at the source.
    ///
    /// # Errors
    ///
    /// Returns validation, authentication, transport, or protocol errors.
    async fn resolve_principal(
        &self,
        reference: &ExternalPrincipalRef,
    ) -> Result<Option<PrincipalProjection>, PrincipalDiscoveryError>;
}

/// Search-capable external identity source: bounded search plus re-resolution.
///
/// A pure type alias for the trait-object spelling; connectors implement
/// [`IPrincipalDiscovery`] with `PrincipalSearchQuery` input directly.
pub type PrincipalSearchDiscovery =
    dyn IPrincipalDiscovery<PrincipalSearchQuery, Output = PrincipalSearchPage>;

/// Supplies a short-lived bearer token for a federated provider's management API.
#[async_trait]
pub trait BearerTokenProvider: Send + Sync + 'static {
    /// Returns a bearer token valid for the provider's management API.
    ///
    /// # Errors
    ///
    /// Returns an authentication or provider-availability error.
    async fn bearer_token(&self) -> Result<String, PrincipalDiscoveryError>;
}

/// Runtime request binding for one custom in-house identity API.
///
/// Query parameters transport the runtime search/resolve values; the optional
/// body template is rendered for POST requests with the same placeholder
/// values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CustomRequestBinding {
    pub path: String,
    /// Query parameter carrying the search text (e.g. `search`).
    pub text_param: String,
    /// Query parameter carrying the 0-based page offset (e.g. `offset`).
    pub offset_param: String,
    /// Query parameter carrying the page size (e.g. `limit`).
    pub limit_param: String,
    /// Query parameter carrying the external ID during resolve (e.g. `id`).
    pub external_id_param: String,
    /// Optional JSON body template for POST requests.
    pub body_template: Option<String>,
}

impl CustomRequestBinding {
    /// Placeholder names rendered in `{{name}}` tokens of the path and the
    /// optional body template.
    pub const SEARCH_PLACEHOLDER: &'static str = "search";
    pub const OFFSET_PLACEHOLDER: &'static str = "offset";
    pub const LIMIT_PLACEHOLDER: &'static str = "limit";
    pub const KIND_PLACEHOLDER: &'static str = "kind";
    pub const EXTERNAL_ID_PLACEHOLDER: &'static str = "external_id";
}

impl From<&crate::config::CustomRequestBindingConfig> for CustomRequestBinding {
    fn from(config: &crate::config::CustomRequestBindingConfig) -> Self {
        Self {
            path: config.path.clone(),
            text_param: config.text_param.clone(),
            offset_param: config.offset_param.clone(),
            limit_param: config.limit_param.clone(),
            external_id_param: config.external_id_param.clone(),
            body_template: config.body_template.clone(),
        }
    }
}

/// Runtime response attribute mapping for one custom in-house identity API.
///
/// `array_path` selects the result array inside the JSON payload with a
/// JSON-pointer path such as `/data/items`; an empty path means the payload is
/// itself the array. <https://www.rfc-editor.org/rfc/rfc6901.html>
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CustomResponseMapping {
    pub array_path: String,
    pub id_attr: String,
    pub display_name_attr: String,
    pub username_attr: Option<String>,
    pub email_attr: Option<String>,
    pub enabled_attr: Option<String>,
    pub kind_attr: Option<String>,
}

impl From<&crate::config::CustomResponseMappingConfig> for CustomResponseMapping {
    fn from(config: &crate::config::CustomResponseMappingConfig) -> Self {
        Self {
            array_path: config.array_path.clone(),
            id_attr: config.id_attr.clone(),
            display_name_attr: config.display_name_attr.clone(),
            username_attr: config.username_attr.clone(),
            email_attr: config.email_attr.clone(),
            enabled_attr: config.enabled_attr.clone(),
            kind_attr: config.kind_attr.clone(),
        }
    }
}

/// Compatibility name retained for management API callers during migration.
pub type ExternalPrincipal = PrincipalProjection;

/// Builds the principal discovery providers from the configured sources and
/// wires them into one [`PrincipalHandler`].
///
/// The startup logic for JIT, federated search, and SCIM lives here instead of
/// in the server: each connector consumes its serde config sub-object
/// directly, and credential files are resolved exactly once at startup.
pub struct PrincipalDiscoveryComponent {
    handler: PrincipalHandler,
}

impl PrincipalDiscoveryComponent {
    /// Opens the JIT projection, the enabled federated search connectors, and
    /// the optional SCIM projection into a ready [`PrincipalHandler`].
    ///
    /// # Errors
    ///
    /// Returns a configuration or credential-file error.
    pub fn new(
        repository: Arc<dyn crate::storage::PrincipalRepository>,
        config: &crate::config::PrincipalDiscoveryConfig,
    ) -> anyhow::Result<Self> {
        let jit = config
            .jit
            .enabled
            .then(|| {
                JitPrincipalDiscovery::new(
                    config.jit.discovery_id.clone(),
                    config.jit.trusted_issuers.clone(),
                    config.jit.allow_insecure_http,
                )
            })
            .transpose()
            .context("configure OIDC JIT Principal discovery")?;
        let mut federated: Vec<Arc<PrincipalSearchDiscovery>> = Vec::new();
        for keycloak in config.federated.keycloak.iter().filter(|entry| entry.enabled) {
            let secret = Self::credential(
                &keycloak.client_secret,
                &keycloak.client_secret_file,
                "Keycloak client secret",
            )?;
            let provider = KeycloakPrincipalDiscovery::with_client_credentials(
                keycloak,
                &keycloak.client_id,
                secret,
            )
            .context("configure Keycloak Principal discovery")?;
            Self::add_search_provider(&mut federated, provider)?;
        }
        for ldap in config.federated.ldap.iter().filter(|entry| entry.enabled) {
            let password = Self::credential(
                &ldap.bind_password,
                &ldap.bind_password_file,
                "LDAP bind password",
            )?;
            let mut resolved = ldap.clone();
            resolved.bind_password = password;
            let provider = LdapPrincipalDiscovery::new(&resolved)
                .context("configure LDAP Principal discovery")?;
            Self::add_search_provider(&mut federated, provider)?;
        }
        for custom in config.federated.custom.iter().filter(|entry| entry.enabled) {
            let token =
                Self::credential(&custom.jwt_token, &custom.jwt_token_file, "custom JWT token")?;
            let mut resolved = custom.clone();
            resolved.jwt_token = token;
            let provider = CustomPrincipalDiscovery::new(&resolved)
                .context("configure custom Principal discovery")?;
            Self::add_search_provider(&mut federated, provider)?;
        }
        let scim = config
            .scim
            .enabled
            .then(|| {
                ScimPrincipalDiscovery::new(
                    config.scim.discovery_id.clone(),
                    config.scim.issuer.clone(),
                )
            })
            .transpose()
            .context("configure SCIM Principal discovery")?;
        let federated_provider_count = federated.len();
        let handler = PrincipalHandler::new(repository, jit, federated, scim);
        tracing::info!(
            authguard.principal.jit_enabled = config.jit.enabled,
            authguard.principal.federated_provider_count = federated_provider_count,
            authguard.principal.scim_enabled = config.scim.enabled,
            "principal discovery providers configured"
        );
        Ok(Self { handler })
    }

    #[must_use]
    pub fn handler(&self) -> PrincipalHandler {
        self.handler.clone()
    }

    /// Adds one search provider, rejecting duplicate protocol identifiers.
    ///
    /// Each `FED_KEYCLOAK`/`FED_LDAP`/`FED_CUSTOM` protocol may be configured
    /// at most once, because search filtering and resolution dispatch on the
    /// protocol identifier.
    fn add_search_provider<T>(
        providers: &mut Vec<Arc<PrincipalSearchDiscovery>>,
        provider: T,
    ) -> anyhow::Result<()>
    where
        T: IPrincipalDiscovery<PrincipalSearchQuery, Output = PrincipalSearchPage>,
    {
        let protocol = provider.provider();
        if providers.iter().any(|existing| existing.provider() == protocol) {
            anyhow::bail!(PrincipalDiscoveryError::InvalidConfiguration(format!(
                "search provider protocol `{protocol}` is already configured"
            )));
        }
        providers.push(Arc::new(provider));
        Ok(())
    }

    /// Resolves one file-or-inline credential value.
    fn credential(value: &str, file: &str, name: &str) -> anyhow::Result<String> {
        if !value.is_empty() {
            return Ok(value.to_string());
        }
        let value = std::fs::read_to_string(file)
            .with_context(|| format!("read {name} file"))?
            .trim_end_matches(['\r', '\n'])
            .to_string();
        if value.is_empty() {
            return Err(anyhow::anyhow!("{name} file is empty"));
        }
        Ok(value)
    }
}
