use thiserror::Error;

pub mod context;
pub mod http_matcher;
pub mod jwt;
pub mod policy_urn;
pub mod protocol;
pub mod sql;

pub use context::*;
pub use http_matcher::{resolve_route, CompiledHttpRoute, HttpMappingError, ResolvedHttpRoute};
pub use policy_urn::*;
pub use protocol::access_context_v1;
pub use sql::*;

pub const MAX_CANONICAL_ID_BYTES: usize = 512;

#[derive(Debug, Error, PartialEq, Eq)]
#[error("{field} must contain 1 to 512 canonical bytes")]
pub struct CanonicalValueError {
    pub field: &'static str,
}

/// Validates an identifier without copying or exposing it in an error/log.
///
/// # Errors
///
/// Rejects empty, whitespace-padded, control-character, or oversized values.
pub fn validate_canonical(value: &str, field: &'static str) -> Result<(), CanonicalValueError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > MAX_CANONICAL_ID_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(CanonicalValueError { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_values_are_bounded_and_trimmed() {
        assert!(validate_canonical("P123", "principal_id").is_ok());
        assert!(validate_canonical(" P123", "principal_id").is_err());
        assert!(validate_canonical("P\n123", "principal_id").is_err());
    }
}
