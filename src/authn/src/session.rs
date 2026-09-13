//! Unified `AuthGuard` session/JWT issuer and verifier.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use authguard_common::config::{AuthnProperties, SessionProperties};
use authguard_common::model::{AuthenticatedPrincipalContext, AuthenticationResult};
use authguard_common::utils::jwt::{load_signing_key, public_key_pem, sign, verify, JwtSigningKey};
use axum::http::HeaderMap;
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Clone)]
pub struct SessionIssuer {
    config: SessionProperties,
    signing_key: Option<JwtSigningKey>,
    public_key: Option<String>,
}

#[derive(Clone, Copy, Debug, Error)]
pub enum SessionError {
    #[error("canonical session signing is unavailable")]
    SigningUnavailable,
    #[error("canonical session token is invalid")]
    InvalidToken,
}

impl SessionIssuer {
    /// Builds the sole session issuer from `AuthN` configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing or invalid signing key.
    pub fn from_config(config: &AuthnProperties) -> anyhow::Result<Self> {
        let key = if config.session.private_key_file.is_empty() {
            config.session.private_key.clone()
        } else {
            std::fs::read_to_string(&config.session.private_key_file)
                .context("read AuthN session private key")?
        };
        let authn_enabled =
            !config.providers.is_empty() || config.standalone.enabled || config.wallet.enabled;
        if key.is_empty() && authn_enabled {
            anyhow::bail!(
                "authn.session privateKey or privateKeyFile is required when AuthN is enabled"
            );
        }
        let signing_key = (!key.is_empty()).then(|| load_signing_key(&key)).transpose()?;
        let public_key = signing_key.as_ref().map(public_key_pem).transpose()?;
        Ok(Self { config: config.session.clone(), signing_key, public_key })
    }

    /// Issues the common `AuthGuard` JWT for any authentication protocol.
    ///
    /// # Errors
    ///
    /// Returns an error when signing is unavailable or serialization fails.
    pub fn issue(
        &self,
        principal: &AuthenticatedPrincipalContext,
        authentication: &AuthenticationResult,
    ) -> Result<String, SessionError> {
        let key = self.signing_key.as_ref().ok_or(SessionError::SigningUnavailable)?;
        let now = epoch_seconds();
        let auth_time = u64::try_from(authentication.authenticated_at.timestamp())
            .map_err(|_| SessionError::SigningUnavailable)?;
        let mut claims = principal
            .trusted_claims
            .iter()
            .map(|(name, value)| (name.clone(), json!(value)))
            .collect::<serde_json::Map<_, _>>();
        claims.extend([
            ("iss".to_string(), json!(self.config.issuer)),
            ("aud".to_string(), json!(self.config.audience)),
            ("sub".to_string(), json!(principal.principal_id)),
            ("principal_id".to_string(), json!(principal.principal_id)),
            ("principal_kind".to_string(), json!(principal.kind.as_str())),
            ("authguard_group_ids".to_string(), json!(principal.stable_group_ids)),
            ("amr".to_string(), json!(authentication.amr)),
            ("auth_time".to_string(), json!(auth_time)),
            ("iat".to_string(), json!(now)),
            ("exp".to_string(), json!(now.saturating_add(self.config.ttl.as_secs()))),
        ]);
        if let Some(acr) = &authentication.acr {
            claims.insert("acr".to_string(), json!(acr));
        }
        let payload = serde_json::to_vec(&Value::Object(claims))
            .map_err(|_| SessionError::SigningUnavailable)?;
        sign(key, &payload).map_err(|_| SessionError::SigningUnavailable)
    }

    /// Verifies the current `AuthGuard` bearer session and returns its Principal ID.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, malformed, expired, or wrongly scoped JWTs.
    pub fn authenticate_bearer(&self, headers: &HeaderMap) -> Result<String, SessionError> {
        let token = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(bearer_value)
            .ok_or(SessionError::InvalidToken)?;
        let payload =
            verify(self.public_key.as_deref().ok_or(SessionError::SigningUnavailable)?, token)
                .map_err(|_| SessionError::InvalidToken)?;
        let claims: Value =
            serde_json::from_slice(&payload).map_err(|_| SessionError::InvalidToken)?;
        let claims = claims.as_object().ok_or(SessionError::InvalidToken)?;
        let principal_id = claims
            .get("principal_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(SessionError::InvalidToken)?;
        if claims.get("sub").and_then(Value::as_str) != Some(principal_id)
            || claims.get("iss").and_then(Value::as_str) != Some(self.config.issuer.as_str())
            || !audience_matches(claims.get("aud"), &self.config.audience)
            || claims.get("exp").and_then(Value::as_u64).is_none_or(|exp| exp <= epoch_seconds())
        {
            return Err(SessionError::InvalidToken);
        }
        Ok(principal_id.to_string())
    }

    #[must_use]
    pub const fn ttl(&self) -> std::time::Duration {
        self.config.ttl
    }
}

fn bearer_value(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty()).then(|| token.trim())
}

fn audience_matches(value: Option<&Value>, expected: &str) -> bool {
    match value {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(values)) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

fn epoch_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use authguard_common::model::{ExternalIdentity, PrincipalKind};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use chrono::{TimeZone as _, Utc};

    use super::*;

    const TEST_PRIVATE_KEY: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../use-cases/customer-growth-job-service/e2e/config/e2e-jwt-keys/resign-jwt-key.pem"
    ));

    #[test]
    fn every_protocol_uses_the_same_canonical_jwt_claims() {
        let mut config = AuthnProperties::default();
        config.standalone.enabled = true;
        config.session.private_key = TEST_PRIVATE_KEY.to_string();
        let issuer = SessionIssuer::from_config(&config).expect("session issuer");
        let principal = AuthenticatedPrincipalContext {
            principal_id: "P_canonical".to_string(),
            kind: PrincipalKind::User,
            stable_group_ids: vec!["G_team".to_string()],
            trusted_claims: HashMap::new(),
            acr: None,
            amr: Vec::new(),
        };
        let authenticated_at = Utc.timestamp_opt(1_700_000_000, 0).single().expect("timestamp");
        let authentication = AuthenticationResult::new(
            ExternalIdentity {
                provider: "wallet".to_string(),
                issuer: "caip-122".to_string(),
                subject: "eip155:1:0x0000000000000000000000000000000000000001".to_string(),
                claims: BTreeMap::new(),
            },
            ["wallet", "siwx", "eoa"],
            Some("urn:authguard:acr:wallet-possession".to_string()),
            authenticated_at,
        );

        let token = issuer.issue(&principal, &authentication).expect("canonical JWT");
        let payload = token.split('.').nth(1).expect("payload");
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url payload"))
                .expect("JSON claims");

        assert_eq!(claims["sub"], "P_canonical");
        assert_eq!(claims["principal_id"], "P_canonical");
        assert_eq!(claims["amr"], json!(["wallet", "siwx", "eoa"]));
        assert_eq!(claims["acr"], "urn:authguard:acr:wallet-possession");
        assert_eq!(claims["auth_time"], 1_700_000_000_u64);
        assert!(claims["iat"].as_u64().is_some());
        assert!(claims["exp"].as_u64() > claims["iat"].as_u64());
        assert!(claims.get("provider").is_none());
        assert!(claims.get("subject").is_none());

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("authorization header"),
        );
        assert_eq!(issuer.authenticate_bearer(&headers).expect("valid token"), "P_canonical");
    }
}
