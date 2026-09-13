use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use super::{ExternalIdentity, ExternalIdentityKey};

/// Persisted standalone credential category. Passkeys and security keys are
/// both `WebAuthn` credentials and intentionally share one kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StandaloneCredentialKind {
    Password,
    Totp,
    Webauthn,
}

impl StandaloneCredentialKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Totp => "totp",
            Self::Webauthn => "webauthn",
        }
    }
}

impl TryFrom<String> for StandaloneCredentialKind {
    type Error = CredentialModelError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "password" => Ok(Self::Password),
            "totp" => Ok(Self::Totp),
            "webauthn" => Ok(Self::Webauthn),
            _ => Err(CredentialModelError::InvalidKind(value)),
        }
    }
}

/// One active credential owned by a standalone `ExternalIdentity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IamStandaloneCredential {
    pub id: String,
    pub identity: ExternalIdentityKey,
    pub kind: StandaloneCredentialKind,
    pub credential_key: Option<String>,
    pub secret_data: Option<String>,
    pub credential_data: Option<Value>,
}

/// Credential lookup result with its owning protocol-neutral identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandaloneCredentialIdentity {
    pub external_identity: ExternalIdentity,
    pub credential: IamStandaloneCredential,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CredentialModelError {
    #[error("unsupported standalone credential kind `{0}`")]
    InvalidKind(String),
}
