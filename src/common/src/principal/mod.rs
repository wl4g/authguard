pub mod custom;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub use crate::model::PrincipalKind;
pub use custom::CustomPrincipalDiscovery;

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

/// Materializes a discovered candidate into the canonical Principal that `AuthN`
/// has already resolved or created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalMaterializationRequest {
    pub principal_id: String,
    pub reference: ExternalPrincipalRef,
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
    /// Configured provider instance identifiers (`discovery_id`). When empty,
    /// all configured providers are searched.
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

    #[must_use]
    pub fn supports_kind(&self, kind: PrincipalKind) -> bool {
        self.kinds.is_empty() || self.kinds.contains(&kind)
    }

    #[must_use]
    pub fn cursor_key(provider_id: &str, stream: &str) -> String {
        format!("{provider_id}:{stream}")
    }

    /// Decodes the decimal offset cursor used by HTTP directory providers.
    ///
    /// # Errors
    ///
    /// Returns an invalid-query error when the provider cursor is not an unsigned integer.
    pub fn offset_cursor(
        &self,
        provider_id: &str,
        stream: &str,
    ) -> Result<u32, PrincipalDiscoveryError> {
        let key = Self::cursor_key(provider_id, stream);
        self.cursor_for(&key).map_or(Ok(0), |value| {
            value.parse().map_err(|_| {
                PrincipalDiscoveryError::InvalidQuery(format!(
                    "cursor for provider `{key}` is invalid"
                ))
            })
        })
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
///
/// # Errors
///
/// Returns an error for blank/oversized text or an invalid page size.
pub fn validate_search_query(query: &PrincipalSearchQuery) -> Result<(), PrincipalDiscoveryError> {
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

#[derive(Debug, Error)]
pub enum PrincipalDiscoveryError {
    #[error("invalid IamPrincipalInfo discovery configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid principal search query: {0}")]
    InvalidQuery(String),
    #[error("unknown IamPrincipalInfo discovery source `{0}`")]
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

    /// Returns the configured provider identity (`discovery_id`) stamped as
    /// the `provider_id` of every projection this provider produces.
    ///
    /// The protocol string is only a capability label; the `provider_id` is
    /// the value callers echo back when re-resolving or materializing a
    /// search candidate.
    fn provider_id(&self) -> &str;

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

/// Search-capable discovery specialization used by `AuthZ` federation.
pub trait IPrincipalSearchDiscovery:
    IPrincipalDiscovery<PrincipalSearchQuery, Output = PrincipalSearchPage>
{
}

impl<T> IPrincipalSearchDiscovery for T where
    T: IPrincipalDiscovery<PrincipalSearchQuery, Output = PrincipalSearchPage>
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
