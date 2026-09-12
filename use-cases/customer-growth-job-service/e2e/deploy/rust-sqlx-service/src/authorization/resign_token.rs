//! Business-microservice proof boundary for the resign-JWT scenario.
//!
//! Authguard re-signs every allowed request as a short-lived RS256 JWT with
//! `authguardOrigin: true` and replaces the authorization header. A workload
//! verifying that signature with the paired public key proves the request
//! passed through Envoy Gateway and rejects direct client calls — client JWTs
//! never carry the marker claim.
//!
//! The verifier is optional: without `RESIGN_TOKEN_PUBLIC_KEY_FILE` the filter
//! passes every request, so the same service image runs in the portable
//! scenarios and in the k3s resign-JWT scenario.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    http::{header::AUTHORIZATION, HeaderValue, Request},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::signature::Verifier as _;
use rsa::{pkcs1v15::VerifyingKey, sha2::Sha256, RsaPublicKey};

const RESIGN_TOKEN_PUBLIC_KEY_FILE_ENV: &str = "RESIGN_TOKEN_PUBLIC_KEY_FILE";
const MAX_CLOCK_SKEW: Duration = Duration::from_secs(5);
/// `{"alg":"RS256","typ":"JWT"}` — the fixed header used by the Authguard signer.
const JWT_HEADER: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";

/// RSA public-key verifier for Authguard resign JWTs.
#[derive(Clone)]
pub struct ResignTokenVerifier {
    public_key: RsaPublicKey,
}

impl ResignTokenVerifier {
    /// Builds the verifier from `RESIGN_TOKEN_PUBLIC_KEY_FILE`; `None` disables
    /// the proof boundary (portable scenario mode).
    ///
    /// # Errors
    ///
    /// Returns an error when the environment variable names an unreadable or
    /// invalid PKCS#1 public-key PEM file.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let Some(path) = std::env::var(RESIGN_TOKEN_PUBLIC_KEY_FILE_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            return Ok(None);
        };
        let pem = std::fs::read_to_string(&path).map_err(|error| {
            anyhow::anyhow!("read {RESIGN_TOKEN_PUBLIC_KEY_FILE_ENV} file {path}: {error}")
        })?;
        let public_key = RsaPublicKey::from_pkcs1_pem(&pem).map_err(|error| {
            anyhow::anyhow!(
                "{RESIGN_TOKEN_PUBLIC_KEY_FILE_ENV} is not a PKCS#1 public PEM: {error}"
            )
        })?;
        Ok(Some(Self { public_key }))
    }

    /// Verifies the request's `Authorization: Bearer` token and the marker claim.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing/unsupported authorization header, an
    /// invalid signature, malformed claims, an expired token, or a payload
    /// without `authguardOrigin: true`.
    pub fn verify(&self, request: &Request<Body>) -> anyhow::Result<()> {
        let token = Self::bearer_token(request)?;
        let payload = self.verified_payload(token)?;
        let claims: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|error| anyhow::anyhow!("invalid resign JWT payload: {error}"))?;
        let origin = claims
            .get("authguardOrigin")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| anyhow::anyhow!("resign JWT is missing authguardOrigin: true"))?;
        if !origin {
            anyhow::bail!("resign JWT marker claim is false");
        }
        let subject = claims
            .get("sub")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("resign JWT is missing the subject claim"))?;
        let expires = claims
            .get("exp")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("resign JWT is missing the expiry claim"))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| anyhow::anyhow!("system clock is before the Unix epoch: {error}"))?
            .as_secs();
        if now.saturating_sub(MAX_CLOCK_SKEW.as_secs()) > expires {
            anyhow::bail!("resign JWT expired");
        }
        tracing::info!(
            authguard.resign_token.subject = subject,
            authguard.resign_token.expires_in_seconds = expires.saturating_sub(now),
            "verified Authguard resign JWT",
        );
        Ok(())
    }

    fn bearer_token(request: &Request<Body>) -> anyhow::Result<&str> {
        let header = request
            .headers()
            .get(AUTHORIZATION)
            .ok_or_else(|| anyhow::anyhow!("authorization header is required"))?;
        Self::bearer_prefix_stripped(header)
            .ok_or_else(|| anyhow::anyhow!("authorization header is not a Bearer token"))
    }

    fn verified_payload(&self, token: &str) -> anyhow::Result<Vec<u8>> {
        let (header, payload, signature) = Self::compact_parts(token)?;
        if header != JWT_HEADER {
            anyhow::bail!("resign JWT header is not the Authguard RS256 header");
        }
        let signature = URL_SAFE_NO_PAD.decode(signature).map_err(|error| {
            anyhow::anyhow!("resign JWT signature is not valid base64url: {error}")
        })?;
        let verifying_key = VerifyingKey::<Sha256>::new(self.public_key.clone());
        let signature = rsa::pkcs1v15::Signature::try_from(signature.as_slice())
            .map_err(|error| anyhow::anyhow!("resign JWT signature is malformed: {error}"))?;
        verifying_key.verify(format!("{header}.{payload}").as_bytes(), &signature).map_err(
            |error| anyhow::anyhow!("resign JWT signature verification failed: {error}"),
        )?;
        URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|error| anyhow::anyhow!("resign JWT payload is not valid base64url: {error}"))
    }

    fn compact_parts(token: &str) -> anyhow::Result<(&str, &str, &str)> {
        let mut parts = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            anyhow::bail!("malformed resign JWT");
        };
        if header.is_empty() || signature.is_empty() {
            anyhow::bail!("malformed resign JWT");
        }
        Ok((header, payload, signature))
    }

    fn bearer_prefix_stripped(header: &HeaderValue) -> Option<&str> {
        let text = header.to_str().ok()?;
        text.strip_prefix("Bearer ").filter(|token| !token.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_prefix_is_stripped() {
        assert_eq!(
            ResignTokenVerifier::bearer_prefix_stripped(&HeaderValue::from_static("Bearer token")),
            Some("token")
        );
        assert_eq!(
            ResignTokenVerifier::bearer_prefix_stripped(&HeaderValue::from_static("Bearer")),
            None
        );
        assert_eq!(
            ResignTokenVerifier::bearer_prefix_stripped(&HeaderValue::from_static("Basic abc")),
            None
        );
    }

    #[test]
    fn compact_token_requires_exactly_three_parts() {
        assert!(ResignTokenVerifier::compact_parts("a.b.c").is_ok());
        assert!(ResignTokenVerifier::compact_parts("a.b").is_err());
        assert!(ResignTokenVerifier::compact_parts("a.b.c.d").is_err());
        assert!(ResignTokenVerifier::compact_parts(".b.c").is_err());
        assert!(ResignTokenVerifier::compact_parts("a.b.").is_err());
    }
}
