use std::collections::BTreeSet;

use reqwest::Url;
use thiserror::Error;

use async_trait::async_trait;

use super::{
    ExternalPrincipalRef, IPrincipalDiscovery, PrincipalDiscoveryError, PrincipalProjection,
    VerifiedOidcPrincipal,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrincipalProjectionError {
    #[error("invalid principal projection configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid verified principal: {0}")]
    InvalidPrincipal(String),
}

/// Converts claims from an already verified OIDC identity into Authguard's
/// protocol-neutral principal model.
///
/// This component neither verifies tokens nor searches an identity provider.
/// Its caller must first validate signature, exact issuer, audience, expiry,
/// and all other authentication requirements. The stable identity key is the
/// exact OIDC `(iss, sub)` pair.
/// <https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability>
#[derive(Debug, Clone)]
pub struct JitPrincipalDiscovery {
    provider_id: String,
    trusted_issuers: BTreeSet<String>,
}

impl JitPrincipalDiscovery {
    /// Creates a projector restricted to explicitly trusted issuers.
    ///
    /// # Errors
    ///
    /// Rejects an invalid provider identifier, an empty issuer set, or an
    /// invalid issuer URL. HTTPS is required unless explicitly relaxed for a
    /// local development environment.
    pub fn new(
        provider_id: impl Into<String>,
        trusted_issuers: impl IntoIterator<Item = String>,
        allow_insecure_http: bool,
    ) -> Result<Self, PrincipalProjectionError> {
        let provider_id = provider_id.into();
        if provider_id.trim().is_empty() || provider_id.trim() != provider_id {
            return Err(PrincipalProjectionError::InvalidConfiguration(
                "provider id must be non-empty and have no surrounding whitespace".to_string(),
            ));
        }

        let mut validated = BTreeSet::new();
        for issuer in trusted_issuers {
            validated.insert(validate_issuer(&issuer, allow_insecure_http)?);
        }
        if validated.is_empty() {
            return Err(PrincipalProjectionError::InvalidConfiguration(
                "at least one trusted OIDC issuer is required".to_string(),
            ));
        }

        Ok(Self { provider_id, trusted_issuers: validated })
    }

    #[must_use]
    pub fn trusted_issuers(&self) -> &BTreeSet<String> {
        &self.trusted_issuers
    }

    /// Produces a local projection candidate without writing to storage.
    ///
    /// # Errors
    ///
    /// Rejects an untrusted issuer or invalid subject identifier.
    pub fn project(
        &self,
        principal: VerifiedOidcPrincipal,
    ) -> Result<PrincipalProjection, PrincipalProjectionError> {
        if !self.trusted_issuers.contains(&principal.issuer) {
            return Err(PrincipalProjectionError::InvalidPrincipal(
                "verified OIDC issuer is not trusted by this projector".to_string(),
            ));
        }
        if principal.subject.is_empty()
            || principal.subject.len() > 512
            || principal.subject.trim() != principal.subject
        {
            return Err(PrincipalProjectionError::InvalidPrincipal(
                "verified OIDC subject must contain 1 to 512 bytes and have no surrounding whitespace"
                    .to_string(),
            ));
        }

        let display_name = principal
            .display_name
            .filter(|value| !value.trim().is_empty())
            .or_else(|| principal.username.clone().filter(|value| !value.trim().is_empty()))
            .or_else(|| principal.email.clone().filter(|value| !value.trim().is_empty()))
            .unwrap_or_else(|| principal.subject.clone());

        Ok(PrincipalProjection {
            reference: ExternalPrincipalRef {
                provider_id: self.provider_id.clone(),
                issuer: principal.issuer,
                external_id: principal.subject,
            },
            kind: principal.kind,
            display_name,
            username: principal.username,
            email: principal.email,
            enabled: principal.enabled,
            attributes: principal.attributes,
        })
    }
}

#[async_trait]
impl IPrincipalDiscovery<VerifiedOidcPrincipal> for JitPrincipalDiscovery {
    type Output = PrincipalProjection;

    fn provider(&self) -> &'static str {
        "JIT"
    }

    async fn discover(
        &self,
        input: VerifiedOidcPrincipal,
    ) -> Result<Self::Output, PrincipalDiscoveryError> {
        self.project(input).map_err(|error| PrincipalDiscoveryError::InvalidResponse {
            provider_id: self.provider_id.clone(),
            message: error.to_string(),
        })
    }

    async fn resolve_principal(
        &self,
        _reference: &ExternalPrincipalRef,
    ) -> Result<Option<PrincipalProjection>, PrincipalDiscoveryError> {
        Err(PrincipalDiscoveryError::InvalidQuery(
            "JIT projection does not search external identity stores".to_string(),
        ))
    }
}

fn validate_issuer(
    issuer: &str,
    allow_insecure_http: bool,
) -> Result<String, PrincipalProjectionError> {
    if issuer.is_empty() || issuer.trim() != issuer {
        return Err(PrincipalProjectionError::InvalidConfiguration(
            "OIDC issuer must be non-empty and have no surrounding whitespace".to_string(),
        ));
    }
    let url = Url::parse(issuer).map_err(|_| {
        PrincipalProjectionError::InvalidConfiguration(
            "OIDC issuer must be an absolute URL".to_string(),
        )
    })?;
    if url.host_str().is_none()
        || url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(PrincipalProjectionError::InvalidConfiguration(
            "OIDC issuer must be hierarchical and have no credentials, query, or fragment"
                .to_string(),
        ));
    }
    if url.scheme() != "https" && !(allow_insecure_http && url.scheme() == "http") {
        return Err(PrincipalProjectionError::InvalidConfiguration(
            "OIDC issuer must use HTTPS unless insecure HTTP is explicitly enabled".to_string(),
        ));
    }
    Ok(issuer.to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const ISSUER: &str = "https://identity.example.com/realms/customer-growth";

    fn projector() -> JitPrincipalDiscovery {
        JitPrincipalDiscovery::new("verified-oidc", [ISSUER.to_string()], false)
            .expect("JIT projector")
    }

    #[test]
    fn projects_exact_issuer_and_subject_identity_key() {
        let mut input = VerifiedOidcPrincipal::user(ISSUER, "user-42");
        input.display_name = Some("Alice Analyst".to_string());
        input.attributes.insert("department".to_string(), json!("growth"));

        let principal = projector().project(input).expect("project");

        assert_eq!(principal.identity_key(), (ISSUER, "user-42"));
        assert_eq!(principal.attributes["department"], json!("growth"));
    }

    #[test]
    fn preserves_valid_trailing_slash_in_exact_issuer() {
        let issuer = "https://identity.example.com/tenant/";
        let projector = JitPrincipalDiscovery::new("verified-oidc", [issuer.to_string()], false)
            .expect("projector");

        let principal =
            projector.project(VerifiedOidcPrincipal::user(issuer, "user-42")).expect("project");

        assert_eq!(principal.reference.issuer, issuer);
    }

    #[test]
    fn rejects_untrusted_issuer() {
        let input = VerifiedOidcPrincipal::user("https://partner.example.com", "user-42");
        assert!(matches!(
            projector().project(input),
            Err(PrincipalProjectionError::InvalidPrincipal(_))
        ));
    }

    #[test]
    fn rejects_blank_subject() {
        assert!(projector().project(VerifiedOidcPrincipal::user(ISSUER, " ")).is_err());
    }

    #[test]
    fn requires_trusted_issuer() {
        assert!(JitPrincipalDiscovery::new("verified-oidc", [], false).is_err());
    }

    #[test]
    fn rejects_insecure_issuer_by_default() {
        assert!(JitPrincipalDiscovery::new(
            "verified-oidc",
            ["http://id.local".to_string()],
            false,
        )
        .is_err());
    }
}
