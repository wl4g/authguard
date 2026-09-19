//! Protocol-neutral authentication convergence and runtime composition.

use std::collections::HashMap;
use std::sync::Arc;

use authguard_common::cache::ICache;
use authguard_common::config::AppConfig;
use authguard_common::model::{
    AuthenticatedPrincipalContext, AuthenticationResult, ExternalIdentityKey, PrincipalKind,
};
use authguard_common::storage::{IdentityBindingRepository, StandaloneCredentialRepository};
use authguard_common::utils::validate_canonical;
use serde_json::Value;
use thiserror::Error;

use crate::authentication::{TokenError, TokenIssuer};
use crate::AccountLinkingProperties;

use crate::principal::{AccountLinkingError, AccountLinkingService};

/// The sole convergence point after protocol-specific proof verification.
pub(crate) struct AuthenticationPipeline {
    linking: AccountLinkingService<Arc<dyn IdentityBindingRepository>>,
    tokens: TokenIssuer,
}

/// Canonical Principal plus the one unified `AuthGuard` bearer token.
pub(crate) struct IssuedAuthentication {
    pub access_token: String,
    pub expires_in: u64,
    pub principal: AuthenticatedPrincipalContext,
}

#[derive(Debug, Error)]
pub(crate) enum AuthenticationPipelineError {
    #[error(transparent)]
    Linking(#[from] AccountLinkingError),
    #[error(transparent)]
    Token(#[from] TokenError),
    #[error("step-up identity does not belong to the authenticated Principal")]
    StepUpPrincipalMismatch,
}

impl AuthenticationPipeline {
    fn new(
        policy: AccountLinkingProperties,
        identities: Arc<dyn IdentityBindingRepository>,
        tokens: TokenIssuer,
    ) -> Self {
        Self { linking: AccountLinkingService::new(policy, identities), tokens }
    }

    /// Resolves a verified identity and issues the canonical token.
    pub(crate) async fn login(
        &self,
        authentication: AuthenticationResult,
        kind: PrincipalKind,
    ) -> Result<IssuedAuthentication, AuthenticationPipelineError> {
        let principal = self.linking.resolve_login(&authentication, kind).await?;
        self.issue(&authentication, principal)
    }

    /// Explicitly links a verified identity and issues the canonical token.
    pub(crate) async fn link(
        &self,
        principal_id: &str,
        authentication: AuthenticationResult,
    ) -> Result<IssuedAuthentication, AuthenticationPipelineError> {
        let principal = self.linking.link_identity(principal_id, &authentication).await?;
        self.issue(&authentication, principal)
    }

    /// Validates an existing `AuthGuard` bearer token for explicit linking.
    pub(crate) fn authenticate_token(
        &self,
        headers: &axum::http::HeaderMap,
    ) -> Result<String, TokenError> {
        self.tokens.authenticate_bearer(headers)
    }

    pub(crate) fn authenticate_browser_cookie(
        &self,
        headers: &axum::http::HeaderMap,
    ) -> Result<AuthenticatedPrincipalContext, TokenError> {
        self.tokens.authenticate_cookie(headers)
    }

    /// Authenticates the canonical Principal carried by either an API bearer or
    /// the Hosted Login `HttpOnly` cookie. Protocol handlers use only the stable
    /// Principal ID and never infer ownership from a login identifier.
    pub(crate) fn authenticate_request_principal(
        &self,
        headers: &axum::http::HeaderMap,
    ) -> Result<String, TokenError> {
        if headers.contains_key(axum::http::header::AUTHORIZATION) {
            self.tokens.authenticate_bearer(headers)
        } else {
            self.tokens.authenticate_cookie(headers).map(|principal| principal.principal_id)
        }
    }

    /// Proves that a fresh protocol-specific authentication belongs to the
    /// already authenticated canonical Principal before credential enrollment.
    pub(crate) async fn verify_step_up(
        &self,
        principal_id: &str,
        authentication: &AuthenticationResult,
        kind: PrincipalKind,
    ) -> Result<(), AuthenticationPipelineError> {
        self.resolve_step_up(principal_id, authentication, kind).await?;
        Ok(())
    }

    /// Re-resolves the step-up identity and issues the one canonical JWT after
    /// a credential ceremony completes.
    pub(crate) async fn complete_step_up(
        &self,
        principal_id: &str,
        authentication: AuthenticationResult,
        kind: PrincipalKind,
    ) -> Result<IssuedAuthentication, AuthenticationPipelineError> {
        let principal = self.resolve_step_up(principal_id, &authentication, kind).await?;
        self.issue(&authentication, principal)
    }

    pub(crate) fn jwks(&self) -> Result<Value, TokenError> {
        self.tokens.jwks()
    }

    pub(crate) async fn rollback_identity_binding(
        &self,
        principal_id: &str,
        identity: &ExternalIdentityKey,
    ) -> Result<(), AuthenticationPipelineError> {
        self.linking.rollback_identity_binding(principal_id, identity).await?;
        Ok(())
    }

    fn issue(
        &self,
        authentication: &AuthenticationResult,
        mut principal: AuthenticatedPrincipalContext,
    ) -> Result<IssuedAuthentication, AuthenticationPipelineError> {
        project_authorization_context(&mut principal, authentication);
        let access_token = self.tokens.issue(&principal, authentication)?;
        Ok(IssuedAuthentication {
            access_token,
            expires_in: self.tokens.ttl().as_secs(),
            principal,
        })
    }

    async fn resolve_step_up(
        &self,
        principal_id: &str,
        authentication: &AuthenticationResult,
        kind: PrincipalKind,
    ) -> Result<AuthenticatedPrincipalContext, AuthenticationPipelineError> {
        let principal = self.linking.resolve_login(authentication, kind).await?;
        if principal.principal_id != principal_id {
            return Err(AuthenticationPipelineError::StepUpPrincipalMismatch);
        }
        Ok(principal)
    }
}

/// Projects only bounded, provider-approved context into the canonical token.
/// Profile data and protocol material remain on the authentication side of the
/// boundary. Account linking therefore stays unaware of claims and protocols.
fn project_authorization_context(
    principal: &mut AuthenticatedPrincipalContext,
    authentication: &AuthenticationResult,
) {
    const MAX_GROUPS: usize = 128;
    const MAX_GROUP_BYTES: usize = 16 * 1_024;
    const MAX_CONTEXT_BYTES: usize = 64 * 1_024;

    let claims = &authentication.external_identity.claims;
    principal.stable_group_ids = claims
        .get("authguard_group_ids")
        .and_then(group_values)
        .filter(|groups| {
            groups.len() <= MAX_GROUPS
                && groups.iter().map(String::len).sum::<usize>() <= MAX_GROUP_BYTES
                && groups
                    .iter()
                    .all(|group| validate_canonical(group, "authguard_group_ids").is_ok())
        })
        .map(|mut groups| {
            groups.sort();
            groups.dedup();
            groups
        })
        .unwrap_or_default();

    let mut context = HashMap::new();
    let mut context_bytes = 0_usize;
    for (name, value) in claims {
        if is_private_or_reserved_claim(name) {
            continue;
        }
        let Some(value) = scalar_claim(value) else {
            continue;
        };
        let size = name.len().saturating_add(value.len());
        if validate_canonical(name, "trusted_claim").is_err()
            || context_bytes.saturating_add(size) > MAX_CONTEXT_BYTES
        {
            continue;
        }
        context_bytes += size;
        context.insert(name.clone(), value);
    }
    principal.trusted_claims = context;
}

fn group_values(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::String(value) => Some(vec![value.clone()]),
        Value::Array(values) => {
            values.iter().map(|value| value.as_str().map(str::to_string)).collect()
        }
        _ => None,
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

fn is_private_or_reserved_claim(name: &str) -> bool {
    matches!(
        name,
        "username"
            | "email"
            | "display_name"
            | "iss"
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

/// Shared runtime dependencies; protocol implementations only borrow what they own.
#[derive(Clone)]
pub(crate) struct AuthnRuntime {
    pub pipeline: Arc<AuthenticationPipeline>,
    pub credentials: Arc<dyn StandaloneCredentialRepository>,
    pub challenges: Option<Arc<dyn ICache>>,
}

impl AuthnRuntime {
    /// Opens protocol-neutral persistence, challenge storage, linking, and token issuance.
    pub(crate) async fn open() -> anyhow::Result<Self> {
        let config = AppConfig::get();
        let storage = config.get_storage();
        let (identities, credentials): (
            Arc<dyn IdentityBindingRepository>,
            Arc<dyn StandaloneCredentialRepository>,
        ) = match storage.provider.to_ascii_lowercase().as_str() {
            "sqlite" => {
                let repository = Arc::new(
                    authguard_common::storage::AuthnSqliteRepository::connect(&storage.sqlite)
                        .await?,
                );
                (repository.clone(), repository)
            }
            "postgres" => {
                let repository = Arc::new(
                    authguard_common::storage::AuthnPostgresRepository::connect(&storage.postgres)
                        .await?,
                );
                (repository.clone(), repository)
            }
            provider => anyhow::bail!("unsupported IAM storage provider `{provider}`"),
        };
        let authn = config.get_authn();
        let challenge_required = !authn.providers.is_empty()
            || authn.wallet.enabled
            || authn.standalone.enabled
                && (authn.standalone.totp.enabled || authn.standalone.webauthn.enabled);
        let challenges = if challenge_required {
            Some(authguard_common::cache::open_cache().await?)
        } else {
            None
        };
        let tokens = TokenIssuer::from_config(authn)?;
        let pipeline = Arc::new(AuthenticationPipeline::new(
            authn.account_linking.clone(),
            identities,
            tokens,
        ));
        Ok(Self { pipeline, credentials, challenges })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use authguard_common::model::{ExternalIdentity, PrincipalKind};
    use chrono::Utc;
    use serde_json::json;

    use super::*;

    #[test]
    fn projects_only_protocol_neutral_authorization_context() {
        let authentication = AuthenticationResult::new(
            ExternalIdentity {
                provider: "corporate".to_string(),
                issuer: "https://id.example".to_string(),
                subject: "employee-123".to_string(),
                claims: BTreeMap::from([
                    ("username".to_string(), json!("alice")),
                    ("email".to_string(), json!("alice@example.com")),
                    ("tenant_id".to_string(), json!("example-corp")),
                    (
                        "authguard_group_ids".to_string(),
                        json!(["principal-team-b", "principal-team-a", "principal-team-a"]),
                    ),
                    ("access_token".to_string(), json!("must-not-leak")),
                ]),
            },
            ["oidc"],
            None,
            Utc::now(),
        );
        let mut principal = AuthenticatedPrincipalContext {
            principal_id: "principal-alice".to_string(),
            kind: PrincipalKind::User,
            stable_group_ids: Vec::new(),
            trusted_claims: HashMap::new(),
            acr: None,
            amr: Vec::new(),
        };

        project_authorization_context(&mut principal, &authentication);

        assert_eq!(principal.stable_group_ids, ["principal-team-a", "principal-team-b"]);
        assert_eq!(
            principal.trusted_claims,
            HashMap::from([("tenant_id".to_string(), "example-corp".to_string())])
        );
    }
}
