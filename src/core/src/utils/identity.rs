use std::collections::{BTreeSet, HashMap};

use axum::http::HeaderMap;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde_json::Value;
use thiserror::Error;

const MAX_IDENTITY_KEY_BYTES: usize = 2_048;
const MAX_GROUPS: usize = 128;
const MAX_GROUP_ID_BYTES: usize = 512;
const MAX_GROUP_BYTES: usize = 16 * 1_024;
const MAX_SCALAR_CLAIM_BYTES: usize = 64 * 1_024;

/// Identity attributes extracted exclusively from an already authenticated request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestIdentity {
    pub issuer: String,
    pub external_id: String,
    pub group_external_ids: Vec<String>,
    pub claims: HashMap<String, String>,
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("missing identity token")]
    Missing,
    #[error("identity token is not a JWT")]
    NotJwt,
    #[error("identity token payload is not valid Base64URL")]
    InvalidBase64,
    #[error("identity token payload is not valid JSON")]
    InvalidJson,
    #[error("identity does not contain a non-empty issuer")]
    MissingIssuer,
    #[error("identity does not contain a non-empty external subject identifier")]
    MissingExternalId,
    #[error("identity groups claim must be a string or string array")]
    InvalidGroups,
    #[error("identity token exceeds Authguard's bounded claim limits")]
    TooLarge,
}

impl RequestIdentity {
    /// Extracts identity only from the configured token header that Envoy has
    /// already authenticated. Client-controlled claim headers are never trusted.
    ///
    /// # Errors
    ///
    /// Returns an error when the trusted token is absent or invalid.
    pub fn from_gateway_headers(
        headers: &HeaderMap,
        token_header: &str,
        issuer_claim: &str,
        external_id_claim: &str,
        groups_claim: &str,
    ) -> Result<Self, IdentityError> {
        Self::from_headers_with_claims(
            headers,
            token_header,
            issuer_claim,
            external_id_claim,
            groups_claim,
        )
    }

    /// Extracts claims from a JWT already authenticated by Envoy Gateway.
    ///
    /// # Errors
    ///
    /// Returns an error when the trusted token header is missing or malformed.
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, IdentityError> {
        Self::from_headers_with_claims(
            headers,
            "x-authguard-id-token",
            "iss",
            "sub",
            "authguard_group_ids",
        )
    }

    /// Extracts configurable claims from a gateway-verified JWT.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured token header or claims are malformed.
    pub fn from_headers_with_claims(
        headers: &HeaderMap,
        token_header: &str,
        issuer_claim: &str,
        external_id_claim: &str,
        groups_claim: &str,
    ) -> Result<Self, IdentityError> {
        let configured = headers
            .get(token_header)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .and_then(|value| {
                if token_header.eq_ignore_ascii_case("authorization") {
                    bearer_value(value)
                } else {
                    Some(value)
                }
            });
        let token = configured.ok_or(IdentityError::Missing)?;
        Self::from_verified_jwt_with_claims(token, issuer_claim, external_id_claim, groups_claim)
    }

    /// Decodes claims from a JWT whose signature and standard claims were already verified.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed tokens or missing `iss`/`sub` claims.
    pub fn from_verified_jwt(token: &str) -> Result<Self, IdentityError> {
        Self::from_verified_jwt_with_claims(token, "iss", "sub", "authguard_group_ids")
    }

    /// Decodes configured claims from a gateway-verified JWT.
    ///
    /// Authentication and signature verification deliberately remain at Envoy Gateway.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed tokens or incompatible claims.
    pub fn from_verified_jwt_with_claims(
        token: &str,
        issuer_claim: &str,
        external_id_claim: &str,
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
        let issuer = object
            .get(issuer_claim)
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty() && value.trim() == *value && value.len() <= MAX_IDENTITY_KEY_BYTES
            })
            .ok_or(IdentityError::MissingIssuer)?
            .to_string();
        let external_id = object
            .get(external_id_claim)
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty() && value.trim() == *value && value.len() <= MAX_IDENTITY_KEY_BYTES
            })
            .ok_or(IdentityError::MissingExternalId)?
            .to_string();
        let group_external_ids = read_groups(object.get(groups_claim))?;
        let mut scalar_bytes = 0usize;
        let mut claims = object
            .iter()
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
        if let Some(amr) = object.get("amr").and_then(Value::as_array) {
            let mfa = amr.iter().any(|value| value.as_str() == Some("mfa"));
            claims.insert("mfa".to_string(), mfa.to_string());
        }
        Ok(Self { issuer, external_id, group_external_ids, claims })
    }
}

fn bearer_value(authorization: &str) -> Option<&str> {
    let (scheme, token) = authorization.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.trim().is_empty() {
        return None;
    }
    Some(token.trim())
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
    if values.len() > MAX_GROUPS {
        return Err(IdentityError::TooLarge);
    }
    let total_bytes = values.iter().map(|value| value.len()).sum::<usize>();
    if total_bytes > MAX_GROUP_BYTES
        || values.iter().any(|value| {
            value.is_empty() || value.trim() != *value || value.len() > MAX_GROUP_ID_BYTES
        })
    {
        return Err(IdentityError::TooLarge);
    }
    Ok(values.into_iter().map(str::to_string).collect::<BTreeSet<_>>().into_iter().collect())
}

fn scalar_claim(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://id.example/realms/company";

    #[test]
    fn extracts_issuer_subject_groups_and_scalar_claims() {
        let payload = URL_SAFE_NO_PAD.encode(
            br#"{"iss":"https://id.example/realms/company","sub":"user-1","authguard_group_ids":["group-7"],"tenant_id":"mycompany"}"#,
        );
        let identity = RequestIdentity::from_verified_jwt(&format!("header.{payload}.signature"))
            .expect("identity");
        assert_eq!(identity.issuer, ISSUER);
        assert_eq!(identity.external_id, "user-1");
        assert_eq!(identity.group_external_ids, ["group-7"]);
        assert_eq!(identity.claims.get("tenant_id").map(String::as_str), Some("mycompany"));
    }

    #[test]
    fn requires_issuer_even_when_subject_is_present() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"user-1"}"#);
        assert!(matches!(
            RequestIdentity::from_verified_jwt(&format!("header.{payload}.signature")),
            Err(IdentityError::MissingIssuer)
        ));
    }

    #[test]
    fn rejects_identity_keys_with_surrounding_whitespace_instead_of_rewriting_them() {
        let payload = URL_SAFE_NO_PAD
            .encode(br#"{"iss":"https://id.example/realms/company","sub":" user-1 "}"#);
        assert!(matches!(
            RequestIdentity::from_verified_jwt(&format!("header.{payload}.signature")),
            Err(IdentityError::MissingExternalId)
        ));
    }

    #[test]
    fn rejects_client_claim_headers_when_verified_token_is_absent() {
        let mut headers = HeaderMap::new();
        headers.insert("x-authguard-issuer", ISSUER.parse().expect("issuer"));
        headers.insert("x-authguard-external-id", "admin".parse().expect("external id"));

        assert!(matches!(
            RequestIdentity::from_gateway_headers(
                &headers,
                "authorization",
                "iss",
                "sub",
                "authguard_group_ids",
            ),
            Err(IdentityError::Missing)
        ));
    }

    #[test]
    fn deduplicates_groups_and_derives_mfa_from_standard_amr() {
        let payload = URL_SAFE_NO_PAD.encode(
            br#"{"iss":"https://id.example/realms/company","sub":"user-1","authguard_group_ids":["group-7","group-7"],"amr":["pwd","mfa"]}"#,
        );
        let identity = RequestIdentity::from_verified_jwt(&format!("header.{payload}.signature"))
            .expect("identity");

        assert_eq!(identity.group_external_ids, ["group-7"]);
        assert_eq!(identity.claims.get("mfa").map(String::as_str), Some("true"));
    }

    #[test]
    fn rejects_unbounded_group_claims() {
        let groups = (0..=MAX_GROUPS).map(|index| format!("group-{index}")).collect::<Vec<_>>();
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "iss": ISSUER,
                "sub": "user-1",
                "authguard_group_ids": groups,
            }))
            .expect("payload"),
        );

        assert!(matches!(
            RequestIdentity::from_verified_jwt(&format!("header.{payload}.signature")),
            Err(IdentityError::TooLarge)
        ));
    }
}
