//! Unified `AuthGuard` JWT issuer and verifier.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use authguard_common::config::{AuthnProperties, TokenProperties};
use authguard_common::model::{AuthenticatedPrincipalContext, AuthenticationResult};
use authguard_common::utils::jwt::{
    load_signing_key, public_key_jwk_components, public_key_pem, sign, verify, JwtSigningKey,
};
use axum::http::HeaderMap;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Clone)]
pub struct TokenIssuer {
    config: TokenProperties,
    signing_key: Option<JwtSigningKey>,
    public_key: Option<String>,
}

#[derive(Clone, Copy, Debug, Error)]
pub enum TokenError {
    #[error("canonical token signing is unavailable")]
    SigningUnavailable,
    #[error("canonical token is invalid")]
    InvalidToken,
}

impl TokenIssuer {
    /// Builds the sole token issuer from `AuthN` configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing or invalid signing key.
    pub fn from_config(config: &AuthnProperties) -> anyhow::Result<Self> {
        let configured_sources = [
            !config.token.private_key.is_empty(),
            !config.token.private_key_b64.is_empty(),
            !config.token.private_key_file.is_empty(),
        ]
        .into_iter()
        .filter(|configured| *configured)
        .count();
        if configured_sources > 1 {
            anyhow::bail!(
                "configure only one of authn.token privateKey, privateKeyB64, or privateKeyFile"
            );
        }
        let key = if !config.token.private_key_b64.is_empty() {
            let decoded = STANDARD
                .decode(config.token.private_key_b64.trim())
                .context("decode authn.token.privateKeyB64")?;
            String::from_utf8(decoded)
                .context("authn.token.privateKeyB64 is not UTF-8 PKCS#8 PEM")?
        } else if !config.token.private_key_file.is_empty() {
            std::fs::read_to_string(&config.token.private_key_file)
                .context("read AuthN token private key")?
        } else {
            config.token.private_key.clone()
        };
        let authn_enabled =
            !config.providers.is_empty() || config.standalone.enabled || config.wallet.enabled;
        if key.is_empty() && authn_enabled {
            anyhow::bail!(
                "authn.token privateKey, privateKeyB64, or privateKeyFile is required when AuthN is enabled"
            );
        }
        let signing_key = (!key.is_empty()).then(|| load_signing_key(&key)).transpose()?;
        let public_key = signing_key.as_ref().map(public_key_pem).transpose()?;
        Ok(Self { config: config.token.clone(), signing_key, public_key })
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
    ) -> Result<String, TokenError> {
        let key = self.signing_key.as_ref().ok_or(TokenError::SigningUnavailable)?;
        let now = epoch_seconds();
        let auth_time = u64::try_from(authentication.authenticated_at.timestamp())
            .map_err(|_| TokenError::SigningUnavailable)?;
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
            .map_err(|_| TokenError::SigningUnavailable)?;
        sign(key, &payload).map_err(|_| TokenError::SigningUnavailable)
    }

    /// Returns the public canonical-token verification key as an RFC 7517 JWKS.
    pub fn jwks(&self) -> Result<Value, TokenError> {
        let key = self.signing_key.as_ref().ok_or(TokenError::SigningUnavailable)?;
        let (modulus, exponent) = public_key_jwk_components(key);
        Ok(json!({"keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": URL_SAFE_NO_PAD.encode(modulus),
            "e": URL_SAFE_NO_PAD.encode(exponent),
        }]}))
    }

    /// Verifies the current `AuthGuard` bearer token and returns its Principal ID.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, malformed, expired, or wrongly scoped JWTs.
    pub fn authenticate_bearer(&self, headers: &HeaderMap) -> Result<String, TokenError> {
        let token = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(bearer_value)
            .ok_or(TokenError::InvalidToken)?;
        Ok(self.authenticate(token)?.principal_id)
    }

    /// Verifies the canonical browser cookie and returns the canonical
    /// Principal context. Cookie extraction is `AuthN` transport handling, not
    /// an authorization concern.
    pub fn authenticate_cookie(
        &self,
        headers: &HeaderMap,
    ) -> Result<AuthenticatedPrincipalContext, TokenError> {
        let token = headers
            .get(axum::http::header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(cookie_token)
            .ok_or(TokenError::InvalidToken)?;
        self.authenticate(token)
    }

    fn authenticate(&self, token: &str) -> Result<AuthenticatedPrincipalContext, TokenError> {
        let payload =
            verify(self.public_key.as_deref().ok_or(TokenError::SigningUnavailable)?, token)
                .map_err(|_| TokenError::InvalidToken)?;
        let claims: Value =
            serde_json::from_slice(&payload).map_err(|_| TokenError::InvalidToken)?;
        let claims = claims.as_object().ok_or(TokenError::InvalidToken)?;
        let principal_id = claims
            .get("principal_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(TokenError::InvalidToken)?;
        if claims.get("sub").and_then(Value::as_str) != Some(principal_id)
            || claims.get("iss").and_then(Value::as_str) != Some(self.config.issuer.as_str())
            || !audience_matches(claims.get("aud"), &self.config.audience)
            || claims.get("exp").and_then(Value::as_u64).is_none_or(|exp| exp <= epoch_seconds())
        {
            return Err(TokenError::InvalidToken);
        }
        AuthenticatedPrincipalContext::from_verified_jwt(token)
            .map_err(|_| TokenError::InvalidToken)
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

fn cookie_token(value: &str) -> Option<&str> {
    value.split(';').map(str::trim).find_map(|entry| {
        entry
            .strip_prefix(crate::handler::TOKEN_COOKIE)
            .and_then(|entry| entry.strip_prefix('='))
            .filter(|token| !token.is_empty())
    })
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
        config.token.private_key = TEST_PRIVATE_KEY.to_string();
        let issuer = TokenIssuer::from_config(&config).expect("token issuer");
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

    #[test]
    fn canonical_issuer_accepts_a_base64_pkcs8_key() {
        let mut config = AuthnProperties::default();
        config.standalone.enabled = true;
        config.token.private_key_b64 = STANDARD.encode(TEST_PRIVATE_KEY);
        TokenIssuer::from_config(&config).expect("base64 canonical token key");
    }
}
