use std::{cell::RefCell, env, error::Error, fmt, sync::Arc, time::Instant};

use async_trait::async_trait;
use authguard_core::model::{
    access_context_v1::access_context_service_client::AccessContextServiceClient,
    AccessContextSigner,
};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use crate::{
    model::{AccessGrantSet, RequestAccess},
    util::{self, ACCESS_CONTEXT_HEADER, SCOPE_TOKEN_HEADER},
};

pub const GRPC_TARGET_ENV: &str = "AUTHGUARD_GRPC_TARGET";
pub const GRPC_TLS_ENV: &str = "AUTHGUARD_GRPC_TLS";
pub const ACCESS_CONTEXT_HMAC_KEY_ENV: &str = "AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY";

pub trait AccessRequest: Send + Sync {
    fn header(&self, name: &str) -> Option<&str>;
}

#[async_trait]
pub trait IAccessContextResolver: Send + Sync {
    fn mode(&self) -> &'static str {
        "custom"
    }

    async fn resolve(
        &self,
        request: &(dyn AccessRequest + Send + Sync),
    ) -> Result<Option<RequestAccess>, AccessError>;
}

#[derive(Debug, Clone)]
pub struct HeaderAccessContextResolver {
    signer: AccessContextSigner,
}

impl HeaderAccessContextResolver {
    /// Creates a direct-header resolver with an explicit shared HMAC key.
    ///
    /// # Errors
    ///
    /// Returns an error when the key contains fewer than 32 bytes.
    pub fn new(key: impl AsRef<[u8]>) -> Result<Self, AccessError> {
        AccessContextSigner::new(key)
            .map(|signer| Self { signer })
            .map_err(|error| AccessError::Resolver(error.to_string()))
    }

    /// Creates a direct-header resolver from `AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY`.
    ///
    /// # Errors
    ///
    /// Returns an error when the environment variable is absent or invalid.
    pub fn from_env() -> Result<Self, AccessError> {
        AccessContextSigner::from_env()
            .map(|signer| Self { signer })
            .map_err(|error| AccessError::Resolver(error.to_string()))
    }
}

#[async_trait]
impl IAccessContextResolver for HeaderAccessContextResolver {
    fn mode(&self) -> &'static str {
        "header"
    }

    async fn resolve(
        &self,
        request: &(dyn AccessRequest + Send + Sync),
    ) -> Result<Option<RequestAccess>, AccessError> {
        let Some(encoded) = request.header(ACCESS_CONTEXT_HEADER).filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        let started = Instant::now();
        let encoded = self.signer.verify(encoded).map_err(|error| {
            tracing::debug!(
                event = "authguard.access_context.verify.failed",
                resolver_mode = "header",
                error_category = util::access_context_error_category(&error),
                duration_ms = util::elapsed_millis(started),
            );
            AccessError::InvalidContext(error.to_string())
        })?;
        let context = util::decode_access_context_internal(&encoded).map_err(|error| {
            tracing::debug!(
                event = "authguard.access_context.verify.failed",
                resolver_mode = "header",
                error_category = util::access_context_error_category(&error),
                duration_ms = util::elapsed_millis(started),
            );
            AccessError::InvalidContext(error.to_string())
        })?;
        tracing::debug!(
            event = "authguard.access_context.verify.succeeded",
            resolver_mode = "header",
            principal_id = %context.principal_id,
            action = %context.action,
            allow_count = context.allow_resource_urns.len(),
            deny_count = context.deny_resource_urns.len(),
            duration_ms = util::elapsed_millis(started),
        );
        Ok(Some(RequestAccess::from_context(&context)))
    }
}

#[async_trait]
pub trait ScopeTokenClient: Send + Sync {
    async fn resolve_scope(&self, token: &str) -> Result<String, AccessError>;
}

#[derive(Debug, Clone)]
pub struct GrpcScopeTokenClient {
    client: AccessContextServiceClient<Channel>,
}

impl GrpcScopeTokenClient {
    /// Creates a reusable lazy gRPC channel from `AUTHGUARD_GRPC_TARGET`.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing target, invalid URI, or invalid TLS flag.
    pub fn from_env() -> Result<Self, AccessError> {
        let target = env::var(GRPC_TARGET_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AccessError::Resolver(format!("{GRPC_TARGET_ENV} is required")))?;
        let tls = parse_bool_env(GRPC_TLS_ENV, false)?;
        tracing::debug!(
            event = "authguard.scope_token.grpc.configured",
            resolver_mode = "grpc",
            tls,
        );
        Self::new(&target, tls)
    }

    /// Creates a reusable lazy gRPC channel for an explicit target.
    ///
    /// # Errors
    ///
    /// Returns an error when the target cannot be represented as a tonic endpoint.
    pub fn new(target: &str, tls: bool) -> Result<Self, AccessError> {
        let endpoint_uri = normalize_target(target, tls);
        let mut endpoint = Endpoint::from_shared(endpoint_uri)
            .map_err(|error| AccessError::Resolver(error.to_string()))?;
        if tls {
            endpoint = endpoint
                .tls_config(ClientTlsConfig::new().with_webpki_roots())
                .map_err(|error| AccessError::Resolver(error.to_string()))?;
        }
        Ok(Self { client: AccessContextServiceClient::new(endpoint.connect_lazy()) })
    }
}

#[async_trait]
impl ScopeTokenClient for GrpcScopeTokenClient {
    async fn resolve_scope(&self, token: &str) -> Result<String, AccessError> {
        let started = Instant::now();
        tracing::debug!(event = "authguard.scope_token.grpc.started", resolver_mode = "grpc",);
        let mut client = self.client.clone();
        match client.resolve_scope(token.to_string()).await {
            Ok(response) => {
                tracing::debug!(
                    event = "authguard.scope_token.grpc.succeeded",
                    resolver_mode = "grpc",
                    duration_ms = util::elapsed_millis(started),
                );
                Ok(response.into_inner())
            }
            Err(error) => {
                tracing::warn!(
                    event = "authguard.scope_token.grpc.failed",
                    resolver_mode = "grpc",
                    grpc_status = %error.code(),
                    duration_ms = util::elapsed_millis(started),
                );
                Err(AccessError::Resolver(error.to_string()))
            }
        }
    }
}

#[derive(Clone)]
pub struct GrpcAccessContextResolver {
    client: Arc<dyn ScopeTokenClient>,
}

impl fmt::Debug for GrpcAccessContextResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("GrpcAccessContextResolver").finish_non_exhaustive()
    }
}

impl GrpcAccessContextResolver {
    #[must_use]
    pub fn new(client: Arc<dyn ScopeTokenClient>) -> Self {
        Self { client }
    }

    /// Creates a resolver backed by `AUTHGUARD_GRPC_TARGET`.
    ///
    /// # Errors
    ///
    /// Returns an error for missing or invalid environment configuration.
    pub fn from_env() -> Result<Self, AccessError> {
        Ok(Self::new(Arc::new(GrpcScopeTokenClient::from_env()?)))
    }
}

#[async_trait]
impl IAccessContextResolver for GrpcAccessContextResolver {
    fn mode(&self) -> &'static str {
        "grpc"
    }

    async fn resolve(
        &self,
        request: &(dyn AccessRequest + Send + Sync),
    ) -> Result<Option<RequestAccess>, AccessError> {
        let Some(token) = request.header(SCOPE_TOKEN_HEADER).filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        let encoded = self.client.resolve_scope(token).await?;
        let context = util::decode_access_context(&encoded)
            .map_err(|error| AccessError::InvalidContext(error.to_string()))?;
        Ok(Some(RequestAccess::from_context(&context)))
    }
}

thread_local! {
    static CURRENT_ACCESS: RefCell<Option<RequestAccess>> = const { RefCell::new(None) };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessError {
    ContextUnavailable,
    ActionMismatch { expected: String, actual: String },
    InvalidContext(String),
    Resolver(String),
}

impl fmt::Display for AccessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContextUnavailable => {
                write!(formatter, "authguard access context is not available")
            }
            Self::ActionMismatch { expected, actual } => {
                write!(
                    formatter,
                    "authguard action mismatch: expected `{expected}`, got `{actual}`"
                )
            }
            Self::InvalidContext(message) => {
                write!(formatter, "invalid authguard access context: {message}")
            }
            Self::Resolver(message) => {
                write!(formatter, "authguard access context resolver failed: {message}")
            }
        }
    }
}

impl Error for AccessError {}

impl AccessError {
    pub(crate) fn category(&self) -> &'static str {
        match self {
            Self::ContextUnavailable => "context_unavailable",
            Self::ActionMismatch { .. } => "action_mismatch",
            Self::InvalidContext(_) => "invalid_context",
            Self::Resolver(_) => "resolver",
        }
    }
}

pub fn set_current(grants: AccessGrantSet) {
    set_current_access(RequestAccess::from_grants(grants));
}

pub fn set_current_access(request_access: RequestAccess) {
    tracing::debug!(
        event = "authguard.access_context.bound",
        principal_id = %request_access.principal_id,
        action = %request_access.action,
        allow_count = request_access.grants.allow_resource_urns.len(),
        deny_count = request_access.grants.deny_resource_urns.len(),
    );
    CURRENT_ACCESS.with(|current| {
        *current.borrow_mut() = Some(request_access);
    });
}

#[must_use]
pub fn get_current() -> Option<AccessGrantSet> {
    get_current_access().map(|access| access.grants)
}

#[must_use]
pub fn get_current_access() -> Option<RequestAccess> {
    CURRENT_ACCESS.with(|current| current.borrow().clone())
}

/// Returns the current request's Authguard grants.
///
/// # Errors
///
/// Returns [`AccessError::ContextUnavailable`] when no grants have been set for
/// the current execution context.
pub fn require_current() -> Result<AccessGrantSet, AccessError> {
    get_current().ok_or_else(|| {
        tracing::debug!(event = "authguard.access_context.required_missing");
        AccessError::ContextUnavailable
    })
}

/// Returns the complete trusted access context for the current request.
///
/// # Errors
///
/// Returns [`AccessError::ContextUnavailable`] when no context has been set.
pub fn require_current_access() -> Result<RequestAccess, AccessError> {
    get_current_access().ok_or_else(|| {
        tracing::debug!(event = "authguard.access_context.required_missing");
        AccessError::ContextUnavailable
    })
}

pub fn clear_current() {
    CURRENT_ACCESS.with(|current| {
        if let Some(access) = current.borrow_mut().take() {
            tracing::debug!(
                event = "authguard.access_context.cleared",
                principal_id = %access.principal_id,
                action = %access.action,
            );
        }
    });
}

fn normalize_target(target: &str, tls: bool) -> String {
    let target = target.trim();
    let target = target.strip_prefix("dns:///").unwrap_or(target);
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else if tls {
        format!("https://{target}")
    } else {
        format!("http://{target}")
    }
}

fn parse_bool_env(name: &str, default: bool) -> Result<bool, AccessError> {
    let Ok(raw) = env::var(name) else {
        return Ok(default);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" | "" => Ok(false),
        _ => Err(AccessError::Resolver(format!("{name} must be a boolean"))),
    }
}
