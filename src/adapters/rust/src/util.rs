use std::{error::Error, fmt, str::FromStr, time::Instant};

pub use authguard_core::model::{SqlCompileError, UrnError};

use crate::{
    access::{self, AccessError},
    model::{
        AccessContext, AccessContextError, RequestAccess, ResourceSqlMapping, SqlScope, UrnPattern,
    },
};

pub const ACCESS_CONTEXT_HEADER: &str = authguard_core::model::ACCESS_CONTEXT_HEADER;
pub const SCOPE_TOKEN_HEADER: &str = authguard_core::model::SCOPE_TOKEN_HEADER;
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Encodes the trusted, versioned context returned by Authguard extAuth.
///
/// # Errors
///
/// Returns an error when JSON serialization fails.
pub fn encode_access_context(context: &AccessContext) -> Result<String, serde_json::Error> {
    context.encode()
}

/// Decodes the trusted, versioned context returned by Authguard extAuth.
///
/// # Errors
///
/// Returns an error for malformed `Base64URL`, JSON, or unsupported versions.
pub fn decode_access_context(encoded: &str) -> Result<AccessContext, AccessContextError> {
    let started = Instant::now();
    match decode_access_context_internal(encoded) {
        Ok(context) => {
            tracing::debug!(
                event = "authguard.access_context.decode.succeeded",
                principal_id = %context.principal_id,
                action = %context.action,
                allow_count = context.allow_resource_urns.len(),
                deny_count = context.deny_resource_urns.len(),
                policy_revision = context.policy_revision,
                duration_ms = elapsed_millis(started),
            );
            Ok(context)
        }
        Err(error) => {
            tracing::debug!(
                event = "authguard.access_context.decode.failed",
                error_category = access_context_error_category(&error),
                duration_ms = elapsed_millis(started),
            );
            Err(error)
        }
    }
}

pub(crate) fn decode_access_context_internal(
    encoded: &str,
) -> Result<AccessContext, AccessContextError> {
    AccessContext::decode(encoded)
}

/// Encodes and signs a context for direct HTTP-header delivery.
///
/// # Errors
///
/// Returns an error for invalid serialization or signing keys.
pub fn sign_access_context(
    context: &AccessContext,
    key: impl AsRef<[u8]>,
) -> Result<String, AccessContextError> {
    let encoded = context.encode()?;
    authguard_core::model::AccessContextSigner::new(key)?.sign_encoded(&encoded)
}

#[derive(Debug)]
pub enum CurrentScopeError {
    Access(AccessError),
    Compile(SqlCompileError),
}

impl fmt::Display for CurrentScopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Access(error) => write!(formatter, "{error}"),
            Self::Compile(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for CurrentScopeError {}

impl From<AccessError> for CurrentScopeError {
    fn from(error: AccessError) -> Self {
        Self::Access(error)
    }
}

impl From<SqlCompileError> for CurrentScopeError {
    fn from(error: SqlCompileError) -> Self {
        Self::Compile(error)
    }
}

/// Parses a Resource URN pattern.
///
/// # Errors
///
/// Returns [`UrnError`] when the URN does not follow Authguard's supported
/// `urn:iam:<partition>:<service>:<region>:<tenant>:<path>` form.
pub fn parse_urn_pattern(raw: &str) -> Result<UrnPattern, UrnError> {
    UrnPattern::from_str(raw)
}

/// Compiles allow/deny Resource URN strings into a SQL scope for a table mapping.
///
/// # Errors
///
/// Returns [`SqlCompileError`] when a Resource URN is invalid or cannot be
/// represented safely as SQL predicates for the supplied mapping.
pub fn compile_scope<A, D>(
    mapping: &ResourceSqlMapping,
    allow: A,
    deny: D,
) -> Result<SqlScope, SqlCompileError>
where
    A: IntoIterator,
    A::Item: AsRef<str>,
    D: IntoIterator,
    D::Item: AsRef<str>,
{
    let started = Instant::now();
    let allow = allow.into_iter().map(|item| item.as_ref().to_string()).collect::<Vec<_>>();
    let deny = deny.into_iter().map(|item| item.as_ref().to_string()).collect::<Vec<_>>();
    tracing::debug!(
        event = "authguard.sql_scope.compile.started",
        allow_count = allow.len(),
        deny_count = deny.len(),
    );
    let result = compile_scope_internal(mapping, &allow, &deny);
    match &result {
        Ok(scope) => tracing::debug!(
            event = "authguard.sql_scope.compile.succeeded",
            allow_count = allow.len(),
            deny_count = deny.len(),
            scope_kind = scope_kind(scope),
            parameter_count = scope.params.len(),
            duration_ms = elapsed_millis(started),
        ),
        Err(error) => tracing::debug!(
            event = "authguard.sql_scope.compile.failed",
            allow_count = allow.len(),
            deny_count = deny.len(),
            error_category = sql_compile_error_category(error),
            duration_ms = elapsed_millis(started),
        ),
    }
    result
}

fn compile_scope_internal(
    mapping: &ResourceSqlMapping,
    allow: &[String],
    deny: &[String],
) -> Result<SqlScope, SqlCompileError> {
    let allow = parse_patterns(allow)?;
    let deny = parse_patterns(deny)?;
    mapping.compile_scope(&allow, &deny)
}

/// Compiles the current execution context's grants into a SQL scope.
///
/// # Errors
///
/// Returns [`CurrentScopeError::Access`] when no grants are present, or
/// [`CurrentScopeError::Compile`] when the grants cannot be represented safely
/// as SQL predicates for the supplied mapping.
pub fn current_scope(mapping: &ResourceSqlMapping) -> Result<SqlScope, CurrentScopeError> {
    let grants = access::require_current()?;
    Ok(compile_scope(
        mapping,
        grants.allow_resource_urns.iter().map(String::as_str),
        grants.deny_resource_urns.iter().map(String::as_str),
    )?)
}

/// Validates the current request action and compiles its grants into a SQL scope.
///
/// # Errors
///
/// Returns an access error for missing or mismatched context and a compile error
/// for grants that cannot be represented by the supplied mapping.
pub fn current_scope_for_action(
    expected_action: &str,
    mapping: &ResourceSqlMapping,
) -> Result<SqlScope, CurrentScopeError> {
    let request_access = access::require_current_access()?;
    scope_for_action(&request_access, expected_action, mapping)
}

/// Validates an explicit request access value and compiles its SQL scope.
///
/// # Errors
///
/// Returns an action mismatch or SQL compilation error.
pub fn scope_for_action(
    request_access: &RequestAccess,
    expected_action: &str,
    mapping: &ResourceSqlMapping,
) -> Result<SqlScope, CurrentScopeError> {
    if request_access.action != expected_action {
        tracing::debug!(
            event = "authguard.sql_scope.action_mismatch",
            principal_id = %request_access.principal_id,
            expected_action,
            actual_action = %request_access.action,
        );
        return Err(AccessError::ActionMismatch {
            expected: expected_action.to_string(),
            actual: request_access.action.clone(),
        }
        .into());
    }
    Ok(compile_scope(
        mapping,
        request_access.grants.allow_resource_urns.iter().map(String::as_str),
        request_access.grants.deny_resource_urns.iter().map(String::as_str),
    )?)
}

pub(crate) fn access_context_error_category(error: &AccessContextError) -> &'static str {
    match error {
        AccessContextError::Base64(_) => "base64",
        AccessContextError::Json(_) => "json",
        AccessContextError::UnsupportedVersion(_) => "unsupported_version",
        AccessContextError::Expired => "expired",
        AccessContextError::IssuedInFuture => "issued_in_future",
        AccessContextError::InvalidLifetime => "invalid_lifetime",
        AccessContextError::InvalidSigningKey => "invalid_signing_key",
        AccessContextError::InvalidSignedFormat => "invalid_signed_format",
        AccessContextError::InvalidSignature => "invalid_signature",
    }
}

fn sql_compile_error_category(error: &SqlCompileError) -> &'static str {
    match error {
        SqlCompileError::InvalidPattern(_) => "invalid_pattern",
        SqlCompileError::UnsupportedRemainderPattern(_) => "unsupported_remainder_pattern",
    }
}

fn scope_kind(scope: &SqlScope) -> &'static str {
    match scope.where_clause.as_str() {
        "0=1" => "deny_all",
        "1=1" => "allow_all",
        _ => "filtered",
    }
}

pub(crate) fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn parse_patterns<I>(patterns: I) -> Result<Vec<UrnPattern>, SqlCompileError>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    patterns
        .into_iter()
        .map(|raw| {
            let raw = raw.as_ref();
            parse_urn_pattern(raw).map_err(|_| SqlCompileError::InvalidPattern(raw.to_string()))
        })
        .collect()
}
