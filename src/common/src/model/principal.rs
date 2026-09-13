use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// `AuthGuard`-owned Principal persisted in `iam_principal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct IamPrincipalInfo {
    pub id: String,
    #[sqlx(try_from = "String")]
    pub kind: PrincipalKind,
    pub display_name: String,
    #[sqlx(try_from = "String")]
    pub status: PrincipalStatus,
    /// Authorization-owned state. Provider claims never belong here.
    #[serde(default)]
    #[sqlx(json)]
    pub authorization_state: BTreeMap<String, Value>,
}

/// Binding persisted in `iam_principal_identity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct IamPrincipalIdentityInfo {
    pub principal_id: String,
    pub provider: String,
    pub issuer: String,
    pub subject: String,
    #[serde(default)]
    pub claims: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrincipalKind {
    User,
    Workload,
    Group,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrincipalStatus {
    Active,
    Disabled,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("unsupported IAM principal {field} `{value}`")]
pub struct PrincipalModelError {
    field: &'static str,
    value: String,
}

impl PrincipalKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "USER",
            Self::Workload => "WORKLOAD",
            Self::Group => "GROUP",
        }
    }
}

impl PrincipalStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Disabled => "DISABLED",
        }
    }
}

impl TryFrom<String> for PrincipalKind {
    type Error = PrincipalModelError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "USER" => Ok(Self::User),
            "WORKLOAD" => Ok(Self::Workload),
            "GROUP" => Ok(Self::Group),
            _ => Err(PrincipalModelError { field: "kind", value }),
        }
    }
}

impl TryFrom<String> for PrincipalStatus {
    type Error = PrincipalModelError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "ACTIVE" => Ok(Self::Active),
            "DISABLED" => Ok(Self::Disabled),
            _ => Err(PrincipalModelError { field: "status", value }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_persisted_principal_enums() {
        assert_eq!(PrincipalKind::try_from("USER".to_string()), Ok(PrincipalKind::User));
        assert_eq!(
            PrincipalStatus::try_from("DISABLED".to_string()),
            Ok(PrincipalStatus::Disabled)
        );
    }

    #[test]
    fn rejects_unknown_persisted_principal_enums() {
        assert!(PrincipalKind::try_from("DEVICE".to_string()).is_err());
        assert!(PrincipalStatus::try_from("PENDING".to_string()).is_err());
    }
}
