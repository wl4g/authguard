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
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub use crate::model::PrincipalKind;
pub use federation::{
    FederatedPrincipalDiscovery, KeycloakPrincipalDiscovery, LdapPrincipalDiscovery,
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
#[async_trait]
pub trait IPrincipalDiscovery<Input>: Send + Sync + 'static
where
    Input: Send + 'static,
{
    type Output: Send + 'static;

    fn id(&self) -> &str;

    /// Executes one discovery operation.
    ///
    /// # Errors
    ///
    /// Returns validation, authentication, transport, or protocol errors.
    async fn discover(&self, input: Input) -> Result<Self::Output, PrincipalDiscoveryError>;
}

/// Narrow capability for resolving one stable external identity.
#[async_trait]
pub trait IPrincipalResolver: Send + Sync + 'static {
    /// Re-resolves a stable external Principal reference.
    ///
    /// # Errors
    ///
    /// Returns validation, authentication, transport, or protocol errors.
    async fn resolve_principal(
        &self,
        reference: &ExternalPrincipalRef,
    ) -> Result<Option<PrincipalProjection>, PrincipalDiscoveryError>;
}

/// Search-capable source that can re-resolve a selected result.
///
/// Implementations may use Keycloak Admin REST, LDAP (RFC 4511), cloud IAM,
/// or a custom enterprise identity API. This protocol-neutral composition
/// avoids coupling the authorization service to a directory product.
/// <https://www.rfc-editor.org/rfc/rfc4511.html>
pub trait IPrincipalSearchDiscovery:
    IPrincipalDiscovery<PrincipalSearchQuery, Output = PrincipalSearchPage> + IPrincipalResolver
where
    Self: Send + Sync + 'static,
{
}

impl<T> IPrincipalSearchDiscovery for T where
    T: IPrincipalDiscovery<PrincipalSearchQuery, Output = PrincipalSearchPage>
        + IPrincipalResolver
        + Send
        + Sync
        + 'static
{
}

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

/// Connection and safety limits for one Keycloak realm.
///
/// Keycloak Admin REST API:
/// <https://www.keycloak.org/docs-api/latest/rest-api/index.html>
#[derive(Debug, Clone)]
pub struct KeycloakPrincipalDiscoveryConfig {
    pub provider_id: String,
    pub base_url: String,
    /// Canonical OIDC issuer used in the `(issuer, external_id)` identity key.
    /// When omitted, it is derived from `base_url` and `realm`.
    pub issuer_url: Option<String>,
    pub realm: String,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_page_size: u32,
    pub allow_insecure_http: bool,
}

/// LDAP object-class and attribute mapping for one Principal kind.
///
/// `object_filter` is a static RFC 4515 filter supplied by an administrator.
/// Runtime query values are never interpolated directly and are always escaped
/// according to RFC 4515.
/// <https://www.rfc-editor.org/rfc/rfc4515.html>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapObjectMapping {
    /// Relative search DN below [`LdapPrincipalDiscoveryConfig::base_dn`].
    pub search_base: String,
    pub object_filter: String,
    pub id_attribute: String,
    pub name_attribute: String,
    pub display_name_attribute: Option<String>,
    pub email_attribute: Option<String>,
    pub enabled_attribute: Option<String>,
    pub search_attributes: Vec<String>,
}

impl LdapObjectMapping {
    #[must_use]
    pub fn new(
        search_base: impl Into<String>,
        object_filter: impl Into<String>,
        id_attribute: impl Into<String>,
        name_attribute: impl Into<String>,
        search_attributes: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            search_base: search_base.into(),
            object_filter: object_filter.into(),
            id_attribute: id_attribute.into(),
            name_attribute: name_attribute.into(),
            display_name_attribute: None,
            email_attribute: None,
            enabled_attribute: None,
            search_attributes: search_attributes.into_iter().collect(),
        }
    }
}

/// Connection, search, and projection settings for one LDAP directory.
///
/// LDAP protocol and filter syntax are defined by RFC 4511 and RFC 4515.
/// Paged search uses the RFC 2696 simple paged-results control.
/// <https://www.rfc-editor.org/rfc/rfc4511.html>
/// <https://www.rfc-editor.org/rfc/rfc4515.html>
/// <https://www.rfc-editor.org/rfc/rfc2696.html>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapPrincipalDiscoveryConfig {
    pub provider_id: String,
    pub url: String,
    /// Stable namespace used with the directory's immutable external ID.
    pub issuer: String,
    pub base_dn: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub user: LdapObjectMapping,
    pub group: LdapObjectMapping,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_page_size: u32,
    pub allow_insecure: bool,
}

impl LdapPrincipalDiscoveryConfig {
    #[must_use]
    pub fn new(
        provider_id: impl Into<String>,
        url: impl Into<String>,
        issuer: impl Into<String>,
        base_dn: impl Into<String>,
        bind_dn: impl Into<String>,
        bind_password: impl Into<String>,
        user: LdapObjectMapping,
        group: LdapObjectMapping,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            url: url.into(),
            issuer: issuer.into(),
            base_dn: base_dn.into(),
            bind_dn: bind_dn.into(),
            bind_password: bind_password.into(),
            user,
            group,
            connect_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(5),
            max_page_size: PrincipalSearchQuery::MAX_PAGE_SIZE,
            allow_insecure: false,
        }
    }
}

/// Compatibility name retained for management API callers during migration.
pub type ExternalPrincipal = PrincipalProjection;

impl KeycloakPrincipalDiscoveryConfig {
    #[must_use]
    pub fn new(
        provider_id: impl Into<String>,
        base_url: impl Into<String>,
        realm: impl Into<String>,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            base_url: base_url.into(),
            issuer_url: None,
            realm: realm.into(),
            connect_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(5),
            max_page_size: PrincipalSearchQuery::MAX_PAGE_SIZE,
            allow_insecure_http: false,
        }
    }
}
