use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

pub const ACCESS_CONTEXT_HEADER: &str = "x-authguard-context";
pub const SCOPE_TOKEN_HEADER: &str = "x-authguard-scope-token";
pub const ACCESS_CONTEXT_VERSION: u8 = 3;
pub const ACCESS_CONTEXT_SIGNING_KEY_ENV: &str = "AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY";
const SIGNED_CONTEXT_PREFIX: &str = "agctx1";
const MIN_SIGNING_KEY_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessContextInput {
    pub principal_id: String,
    pub action: String,
    pub resource_urn: String,
    pub allow_resource_urns: Vec<String>,
    pub deny_resource_urns: Vec<String>,
    pub policy_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessContext {
    pub version: u8,
    #[serde(alias = "subject_id")]
    pub principal_id: String,
    pub action: String,
    pub resource_urn: String,
    pub allow_resource_urns: Vec<String>,
    pub deny_resource_urns: Vec<String>,
    #[serde(alias = "policy_version")]
    pub policy_revision: u64,
    pub issued_at_epoch_seconds: u64,
    pub expires_at_epoch_seconds: u64,
}

#[derive(Debug, Error)]
pub enum AccessContextError {
    #[error("invalid base64url access context: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid access context JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported access context version {0}")]
    UnsupportedVersion(u8),
    #[error("access context has expired")]
    Expired,
    #[error("access context issue time is in the future")]
    IssuedInFuture,
    #[error("access context expiry must be later than issue time")]
    InvalidLifetime,
    #[error("access context signing key must contain at least {MIN_SIGNING_KEY_BYTES} bytes")]
    InvalidSigningKey,
    #[error("invalid signed access context format")]
    InvalidSignedFormat,
    #[error("invalid signed access context signature")]
    InvalidSignature,
}

/// HMAC-SHA256 signer/verifier for direct request-access headers.
#[derive(Clone)]
pub struct AccessContextSigner {
    key: Vec<u8>,
}

impl std::fmt::Debug for AccessContextSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("AccessContextSigner").finish_non_exhaustive()
    }
}

impl AccessContextSigner {
    /// Creates a signer from a high-entropy secret containing at least 32 bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is too short.
    pub fn new(key: impl AsRef<[u8]>) -> Result<Self, AccessContextError> {
        let key = key.as_ref();
        if key.len() < MIN_SIGNING_KEY_BYTES {
            return Err(AccessContextError::InvalidSigningKey);
        }
        Ok(Self { key: key.to_vec() })
    }

    /// Reads the direct-context key from `AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY`,
    /// either from the process environment or from the mounted
    /// `AUTHGUARD_ENV_FILE` KEY=VALUE file.
    ///
    /// # Errors
    ///
    /// Returns an error when the variable is absent, non-Unicode, or too short.
    pub fn from_env() -> Result<Self, AccessContextError> {
        let key = crate::config::secret_env(ACCESS_CONTEXT_SIGNING_KEY_ENV)
            .ok_or(AccessContextError::InvalidSigningKey)?;
        Self::new(key)
    }

    /// Signs an encoded context as `agctx1.<payload>.<base64url-hmac-sha256>`.
    ///
    /// # Errors
    ///
    /// Returns an error only if the configured HMAC key is invalid.
    pub fn sign_encoded(&self, encoded: &str) -> Result<String, AccessContextError> {
        let signing_input = format!("{SIGNED_CONTEXT_PREFIX}.{encoded}");
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .map_err(|_| AccessContextError::InvalidSigningKey)?;
        mac.update(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        Ok(format!("{signing_input}.{signature}"))
    }

    /// Verifies a direct-context compact token and returns its encoded payload.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed tokens or invalid signatures.
    pub fn verify(&self, signed: &str) -> Result<String, AccessContextError> {
        let mut parts = signed.split('.');
        let prefix = parts.next();
        let payload = parts.next();
        let signature = parts.next();
        if prefix != Some(SIGNED_CONTEXT_PREFIX)
            || payload.is_none_or(str::is_empty)
            || signature.is_none_or(str::is_empty)
            || parts.next().is_some()
        {
            return Err(AccessContextError::InvalidSignedFormat);
        }
        let Some(payload) = payload else {
            return Err(AccessContextError::InvalidSignedFormat);
        };
        let Some(signature) = signature else {
            return Err(AccessContextError::InvalidSignedFormat);
        };
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| AccessContextError::InvalidSignedFormat)?;
        let signing_input = format!("{SIGNED_CONTEXT_PREFIX}.{payload}");
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .map_err(|_| AccessContextError::InvalidSigningKey)?;
        mac.update(signing_input.as_bytes());
        mac.verify_slice(&signature).map_err(|_| AccessContextError::InvalidSignature)?;
        Ok(payload.to_string())
    }
}

impl AccessContext {
    #[must_use]
    pub fn new(
        input: AccessContextInput,
        issued_at_epoch_seconds: u64,
        ttl: std::time::Duration,
    ) -> Self {
        Self {
            version: ACCESS_CONTEXT_VERSION,
            principal_id: input.principal_id,
            action: input.action,
            resource_urn: input.resource_urn,
            allow_resource_urns: input.allow_resource_urns,
            deny_resource_urns: input.deny_resource_urns,
            policy_revision: input.policy_revision,
            issued_at_epoch_seconds,
            expires_at_epoch_seconds: issued_at_epoch_seconds.saturating_add(ttl.as_secs()),
        }
    }

    /// Serializes the context as unpadded `Base64URL` JSON for a single HTTP header.
    ///
    /// # Errors
    ///
    /// Returns an error if the context cannot be serialized.
    pub fn encode(&self) -> Result<String, serde_json::Error> {
        serde_json::to_vec(self).map(|json| URL_SAFE_NO_PAD.encode(json))
    }

    /// Decodes a versioned access context HTTP header.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed `Base64URL`, invalid JSON, or unknown versions.
    pub fn decode(encoded: &str) -> Result<Self, AccessContextError> {
        let json = URL_SAFE_NO_PAD.decode(encoded)?;
        let context: Self = serde_json::from_slice(&json)?;
        context.validate(epoch_seconds())?;
        Ok(context)
    }

    /// Validates the version and bounded request lifetime at an explicit time.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported, expired, future-issued, or inverted
    /// lifetimes.
    pub fn validate(&self, now_epoch_seconds: u64) -> Result<(), AccessContextError> {
        if self.version != ACCESS_CONTEXT_VERSION {
            return Err(AccessContextError::UnsupportedVersion(self.version));
        }
        if self.expires_at_epoch_seconds <= self.issued_at_epoch_seconds {
            return Err(AccessContextError::InvalidLifetime);
        }
        if self.issued_at_epoch_seconds > now_epoch_seconds.saturating_add(30) {
            return Err(AccessContextError::IssuedInFuture);
        }
        if self.expires_at_epoch_seconds <= now_epoch_seconds {
            return Err(AccessContextError::Expired);
        }
        Ok(())
    }
}

#[must_use]
pub fn epoch_seconds() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_context_round_trips_as_base64url_json() {
        let now = epoch_seconds();
        let expected = AccessContext::new(
            AccessContextInput {
                principal_id: "principal-user-1".to_string(),
                action: "job.read".to_string(),
                resource_urn: "urn:iam:prod:customer-growth:global:example-corp:job/1".to_string(),
                allow_resource_urns: vec![
                    "urn:iam:prod:customer-growth:global:example-corp:job/*".to_string()
                ],
                deny_resource_urns: Vec::new(),
                policy_revision: 7,
            },
            now,
            std::time::Duration::from_secs(30),
        );
        let encoded = expected.encode().expect("encode");
        assert!(!encoded.contains('='));
        assert_eq!(AccessContext::decode(&encoded).expect("decode"), expected);
    }

    #[test]
    fn expired_context_is_rejected() {
        let context = AccessContext::new(
            AccessContextInput {
                principal_id: "principal-user-1".to_string(),
                action: "job.read".to_string(),
                resource_urn: "urn:iam:prod:customer-growth:global:example-corp:job/1".to_string(),
                allow_resource_urns: Vec::new(),
                deny_resource_urns: Vec::new(),
                policy_revision: 7,
            },
            100,
            std::time::Duration::from_secs(1),
        );
        assert!(matches!(context.validate(101), Err(AccessContextError::Expired)));
    }

    #[test]
    fn direct_context_signature_detects_tampering() {
        let codec = AccessContextSigner::new([7_u8; 32]).expect("signer");
        let compact = codec.sign_encoded("payload").expect("sign");
        assert_eq!(codec.verify(&compact).expect("verify"), "payload");
        assert!(matches!(
            codec.verify(&compact.replace("payload", "tampered")),
            Err(AccessContextError::InvalidSignature)
        ));
    }
}
