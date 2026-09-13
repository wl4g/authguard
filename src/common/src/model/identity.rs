use std::collections::{BTreeMap, HashMap};

use axum::http::HeaderMap;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::model::PrincipalKind;
use crate::utils::validate_canonical;

const MAX_GROUPS: usize = 128;
const MAX_GROUP_BYTES: usize = 16 * 1_024;
const MAX_SCALAR_CLAIM_BYTES: usize = 64 * 1_024;

/// Sole authenticated identity contract accepted by `AuthZ`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatedPrincipalContext {
    pub principal_id: String,
    pub kind: PrincipalKind,
    #[serde(default)]
    pub stable_group_ids: Vec<String>,
    #[serde(default)]
    pub trusted_claims: HashMap<String, String>,
    pub acr: Option<String>,
    #[serde(default)]
    pub amr: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("missing identity token")]
    Missing,
    #[error("identity token is not a JWT")]
    NotJwt,
    #[error("identity token payload is not valid Base64URL")]
    InvalidBase64,
    #[error("identity token payload is not valid JSON")]
    InvalidJson,
    #[error("identity does not contain a non-empty canonical principal ID")]
    MissingPrincipalId,
    #[error("identity does not contain a valid principal kind")]
    InvalidPrincipalKind,
    #[error("identity groups claim must be a string or string array")]
    InvalidGroups,
    #[error("identity token exceeds AuthGuard's bounded claim limits")]
    TooLarge,
}

impl AuthenticatedPrincipalContext {
    /// Extracts canonical identity from a token already verified by Envoy.
    ///
    /// # Errors
    ///
    /// Returns an error for missing or malformed canonical identity claims.
    pub fn from_gateway_headers(
        headers: &HeaderMap,
        token_header: &str,
        principal_id_claim: &str,
        kind_claim: &str,
        groups_claim: &str,
    ) -> Result<Self, IdentityError> {
        let configured = headers
            .get(token_header)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .and_then(|value| {
                token_header
                    .eq_ignore_ascii_case("authorization")
                    .then(|| bearer_value(value))
                    .flatten()
                    .or_else(|| {
                        (!token_header.eq_ignore_ascii_case("authorization")).then_some(value)
                    })
            });
        Self::from_verified_jwt_with_claims(
            configured.ok_or(IdentityError::Missing)?,
            principal_id_claim,
            kind_claim,
            groups_claim,
        )
    }

    /// Decodes a JWT whose signature and standard claims were verified upstream.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or non-canonical claims.
    pub fn from_verified_jwt(token: &str) -> Result<Self, IdentityError> {
        Self::from_verified_jwt_with_claims(
            token,
            "principal_id",
            "principal_kind",
            "authguard_group_ids",
        )
    }

    /// Decodes configured canonical claims from an already verified JWT.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or unbounded claims.
    pub fn from_verified_jwt_with_claims(
        token: &str,
        principal_id_claim: &str,
        kind_claim: &str,
        groups_claim: &str,
    ) -> Result<Self, IdentityError> {
        let parts = token.split('.').collect::<Vec<_>>();
        if parts.len() != 3 || parts[1].is_empty() {
            return Err(IdentityError::NotJwt);
        }
        let payload = URL_SAFE_NO_PAD
            .decode(parts[1])
            .or_else(|_| URL_SAFE.decode(parts[1]))
            .map_err(|_| IdentityError::InvalidBase64)?;
        let value: Value =
            serde_json::from_slice(&payload).map_err(|_| IdentityError::InvalidJson)?;
        let object = value.as_object().ok_or(IdentityError::InvalidJson)?;
        let principal_id = object
            .get(principal_id_claim)
            .and_then(Value::as_str)
            .ok_or(IdentityError::MissingPrincipalId)?;
        validate_canonical(principal_id, "principal_id")
            .map_err(|_| IdentityError::MissingPrincipalId)?;
        let kind = object
            .get(kind_claim)
            .and_then(Value::as_str)
            .and_then(parse_principal_kind)
            .ok_or(IdentityError::InvalidPrincipalKind)?;
        let stable_group_ids = read_groups(object.get(groups_claim))?;
        let mut scalar_bytes = 0usize;
        let mut trusted_claims = object
            .iter()
            .filter(|(name, _)| !is_boundary_claim(name))
            .filter_map(|(name, value)| {
                scalar_claim(value).map(|value| {
                    scalar_bytes = scalar_bytes.saturating_add(name.len() + value.len());
                    (name.clone(), value)
                })
            })
            .collect::<HashMap<_, _>>();
        if scalar_bytes > MAX_SCALAR_CLAIM_BYTES {
            return Err(IdentityError::TooLarge);
        }
        let acr = object.get("acr").and_then(Value::as_str).map(str::to_string);
        let amr = read_string_array(object.get("amr"))?;
        trusted_claims
            .insert("mfa".to_string(), amr.iter().any(|value| value == "mfa").to_string());
        Ok(Self {
            principal_id: principal_id.to_string(),
            kind,
            stable_group_ids,
            trusted_claims,
            acr,
            amr,
        })
    }
}

fn parse_principal_kind(value: &str) -> Option<PrincipalKind> {
    match value {
        "USER" => Some(PrincipalKind::User),
        "WORKLOAD" => Some(PrincipalKind::Workload),
        "GROUP" => Some(PrincipalKind::Group),
        _ => None,
    }
}

fn bearer_value(authorization: &str) -> Option<&str> {
    let (scheme, token) = authorization.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty()).then(|| token.trim())
}

fn read_groups(value: Option<&Value>) -> Result<Vec<String>, IdentityError> {
    let values = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::String(value)) => vec![value.as_str()],
        Some(Value::Array(values)) => values
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .ok_or(IdentityError::InvalidGroups)?,
        Some(_) => return Err(IdentityError::InvalidGroups),
    };
    if values.len() > MAX_GROUPS
        || values.iter().map(|value| value.len()).sum::<usize>() > MAX_GROUP_BYTES
    {
        return Err(IdentityError::TooLarge);
    }
    let mut result = values
        .into_iter()
        .map(|value| {
            validate_canonical(value, "group_id").map_err(|_| IdentityError::InvalidGroups)?;
            Ok(value.to_string())
        })
        .collect::<Result<Vec<_>, IdentityError>>()?;
    result.sort();
    result.dedup();
    Ok(result)
}

fn read_string_array(value: Option<&Value>) -> Result<Vec<String>, IdentityError> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| value.as_str().map(str::to_string).ok_or(IdentityError::InvalidJson))
            .collect(),
        Some(_) => Err(IdentityError::InvalidJson),
    }
}

fn scalar_claim(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn is_boundary_claim(name: &str) -> bool {
    matches!(
        name,
        "iss"
            | "sub"
            | "aud"
            | "iat"
            | "exp"
            | "nbf"
            | "jti"
            | "provider"
            | "access_token"
            | "refresh_token"
            | "authorization_code"
            | "principal_id"
            | "principal_kind"
            | "authguard_group_ids"
            | "acr"
            | "amr"
            | "authguardOrigin"
    )
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    use super::*;

    #[test]
    fn extracts_only_canonical_identity_and_safe_scalar_claims() {
        let payload = URL_SAFE_NO_PAD.encode(
            br#"{"principal_id":"P123","principal_kind":"USER","authguard_group_ids":["G2","G1","G1"],"provider":"github","sub":"987","tenant":"acme","amr":["pwd","mfa"]}"#,
        );
        let context = AuthenticatedPrincipalContext::from_verified_jwt(&format!("x.{payload}.x"))
            .expect("canonical context");
        assert_eq!(context.principal_id, "P123");
        assert_eq!(context.stable_group_ids, ["G1", "G2"]);
        assert!(!context.trusted_claims.contains_key("provider"));
        assert_eq!(context.trusted_claims.get("tenant").map(String::as_str), Some("acme"));
        assert_eq!(context.trusted_claims.get("mfa").map(String::as_str), Some("true"));
    }
}

/// Provider-owned identity produced after authentication and normalization.
///
/// This is not an authorization Principal. Multiple external identities can
/// be bound to one canonical Principal by the account-linking service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalIdentity {
    pub provider: String,
    pub issuer: String,
    pub subject: String,
    #[serde(default)]
    pub claims: BTreeMap<String, Value>,
}

impl ExternalIdentity {
    /// Returns the globally unique binding key.
    ///
    /// # Errors
    ///
    /// Rejects blank, non-canonical, or unreasonably large components.
    pub fn key(&self) -> Result<ExternalIdentityKey, IdentityModelError> {
        ExternalIdentityKey::new(&self.provider, &self.issuer, &self.subject)
    }
}

/// Globally unique external identity binding key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ExternalIdentityKey {
    pub provider: String,
    pub issuer: String,
    pub subject: String,
}

impl ExternalIdentityKey {
    /// Builds a validated identity key.
    ///
    /// # Errors
    ///
    /// Rejects blank, whitespace-padded, or oversized components.
    pub fn new(
        provider: impl Into<String>,
        issuer: impl Into<String>,
        subject: impl Into<String>,
    ) -> Result<Self, IdentityModelError> {
        let key =
            Self { provider: provider.into(), issuer: issuer.into(), subject: subject.into() };
        for (name, value) in [
            ("provider", key.provider.as_str()),
            ("issuer", key.issuer.as_str()),
            ("subject", key.subject.as_str()),
        ] {
            validate_canonical(value, name)
                .map_err(|_| IdentityModelError::InvalidIdentityComponent(name))?;
        }
        Ok(key)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityModelError {
    #[error("external identity {0} must contain 1 to 512 canonical bytes")]
    InvalidIdentityComponent(&'static str),
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IamAuthFlowInfo {
    pub provider: String,
    pub return_uri: String,
    pub expires_at_epoch_seconds: u64,
    pub nonce: Option<String>,
    pub pkce_verifier: Option<String>,
}
