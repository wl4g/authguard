use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Authorization-side projection of an identity owned by an external issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// Authguard-owned stable identifier referenced by role bindings.
    pub id: String,
    /// Canonical external issuer (for OIDC this is the exact `iss` claim).
    pub issuer: String,
    /// Issuer-local stable identifier (for OIDC this is the exact `sub` claim).
    pub external_id: String,
    pub kind: PrincipalKind,
    pub display_name: String,
    pub status: PrincipalStatus,
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrincipalKind {
    User,
    Workload,
    Group,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrincipalStatus {
    Active,
    Disabled,
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
