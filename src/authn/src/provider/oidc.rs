use async_trait::async_trait;
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreProviderMetadata,
};
use openidconnect::{
    AdditionalClaims, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse as _, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse as _, UserInfoClaims,
};
use serde::{Deserialize, Serialize};
use tracing::Instrument as _;

use super::normalization::normalize_identity;
use super::{IProviderAdapter, OAuthLikeCallback, ProviderAuthorization, ProviderError};
use crate::config::OidcProviderProperties;
use crate::model::ExternalIdentity;
use authguard_common::PrincipalKind;

type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

type OidcUserInfoClaims = UserInfoClaims<OidcAdditionalClaims, CoreGenderClaim>;

#[derive(Debug, Serialize, Deserialize)]
struct OidcAdditionalClaims {
    #[serde(flatten)]
    values: std::collections::BTreeMap<String, serde_json::Value>,
}

impl AdditionalClaims for OidcAdditionalClaims {}

/// Standards-compliant OIDC Authorization Code adapter with discovery,
/// nonce validation, PKCE, and ID-token signature/issuer/audience validation.
pub struct OidcProvider {
    provider_id: String,
    config: OidcProviderProperties,
    client: OidcClient,
    http: openidconnect::reqwest::Client,
}

impl OidcProvider {
    /// Discovers one OIDC issuer and pins its metadata/JWKS to this adapter.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration or failed provider discovery.
    pub async fn discover(
        provider_id: impl Into<String>,
        config: OidcProviderProperties,
    ) -> Result<Self, ProviderError> {
        if let Some(introspection) = &config.token_introspection {
            if config.client_secret.is_empty()
                || introspection.accepted_audiences.is_empty()
                || reqwest::Url::parse(&introspection.endpoint).is_err()
            {
                return Err(ProviderError::InvalidConfiguration(
                    "OIDC token introspection requires an endpoint, client secret, and accepted audience",
                ));
            }
        }
        let provider_id = provider_id.into();
        let issuer = IssuerUrl::new(config.issuer.clone())
            .map_err(|_| ProviderError::InvalidConfiguration("invalid OIDC issuer"))?;
        let redirect = RedirectUrl::new(config.callback_url.clone())
            .map_err(|_| ProviderError::InvalidConfiguration("invalid OIDC callback URL"))?;
        let http = openidconnect::reqwest::ClientBuilder::new()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| ProviderError::Transport(error.to_string()))?;
        let metadata = CoreProviderMetadata::discover_async(issuer, &http)
            .await
            .map_err(|error| ProviderError::Transport(error.to_string()))?;
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(config.client_id.clone()),
            (!config.client_secret.is_empty())
                .then(|| ClientSecret::new(config.client_secret.clone())),
        )
        .set_redirect_uri(redirect);
        Ok(Self { provider_id, config, client, http })
    }

    fn authorization(&self, state: &str) -> ProviderAuthorization {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let state = state.to_string();
        let request = self
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                move || CsrfToken::new(state),
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge);
        let (url, _, nonce) = self
            .config
            .scopes
            .iter()
            .filter(|scope| scope.as_str() != "openid")
            .fold(request, |request, scope| request.add_scope(Scope::new(scope.clone())))
            .url();
        ProviderAuthorization {
            url,
            nonce: Some(nonce.secret().clone()),
            pkce_verifier: Some(verifier.secret().clone()),
        }
    }

    async fn userinfo_identity(
        &self,
        access_token: openidconnect::AccessToken,
        expected_subject: Option<openidconnect::SubjectIdentifier>,
    ) -> Result<ExternalIdentity, ProviderError> {
        let request = self.client.user_info(access_token, expected_subject).map_err(|_| {
            ProviderError::InvalidConfiguration("OIDC UserInfo endpoint is missing")
        })?;
        let claims: OidcUserInfoClaims = request
            .request_async(&self.http)
            .await
            .map_err(|error| ProviderError::Transport(error.to_string()))?;
        let claims =
            serde_json::to_value(claims).map_err(|_| ProviderError::InvalidIdentityToken)?;
        normalize_identity(
            &self.provider_id,
            &self.config.issuer,
            &self.config.identity,
            &claims,
            None,
        )
    }

    async fn introspection_identity(
        &self,
        access_token: &str,
    ) -> Result<ExternalIdentity, ProviderError> {
        let introspection =
            self.config.token_introspection.as_ref().ok_or(ProviderError::UnsupportedFlow)?;
        let response = self
            .http
            .post(&introspection.endpoint)
            .basic_auth(&self.config.client_id, Some(&self.config.client_secret))
            .form(&[("token", access_token), ("token_type_hint", "access_token")])
            .send()
            .await
            .map_err(|error| ProviderError::Transport(error.to_string()))?;
        if !response.status().is_success() {
            return Err(ProviderError::ProviderRejected(response.status().as_u16()));
        }
        let claims = response
            .json::<serde_json::Value>()
            .await
            .map_err(|_| ProviderError::InvalidIdentityToken)?;
        if claims.get("active").and_then(serde_json::Value::as_bool) != Some(true)
            || claims.get("iss").and_then(serde_json::Value::as_str)
                != Some(self.config.issuer.as_str())
            || !has_accepted_audience(&claims, &introspection.accepted_audiences)
        {
            return Err(ProviderError::InvalidIdentityToken);
        }
        normalize_identity(
            &self.provider_id,
            &self.config.issuer,
            &self.config.identity,
            &claims,
            None,
        )
    }
}

#[async_trait]
impl IProviderAdapter for OidcProvider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    fn authorization_url(
        &self,
        _client_id: &str,
        _redirect_uri: &str,
        state: &str,
    ) -> Result<reqwest::Url, ProviderError> {
        Ok(self.authorization(state).url)
    }

    fn authorize(
        &self,
        _client_id: &str,
        _redirect_uri: &str,
        state: &str,
    ) -> Result<ProviderAuthorization, ProviderError> {
        Ok(self.authorization(state))
    }

    async fn authenticate(
        &self,
        callback: OAuthLikeCallback,
    ) -> Result<ExternalIdentity, ProviderError> {
        let started = std::time::Instant::now();
        tracing::info!(
            event = "authguard.authn.provider.started",
            provider = %self.provider_id,
            flow = "authorization_code",
            "OIDC provider authentication started"
        );
        let span = tracing::info_span!(
            "authn.provider.authenticate",
            otel.kind = "client",
            authguard.provider = %self.provider_id,
            authguard.provider.type = "oidc",
            authguard.provider.flow = "authorization_code",
        );
        let result = async {
            let nonce = callback.nonce.ok_or(ProviderError::InvalidIdentityToken)?;
            let verifier = callback.pkce_verifier.ok_or(ProviderError::InvalidIdentityToken)?;
            let response = self
                .client
                .exchange_code(AuthorizationCode::new(callback.authorization_code))
                .map_err(|_| ProviderError::InvalidConfiguration("OIDC token endpoint is missing"))?
                .set_pkce_verifier(PkceCodeVerifier::new(verifier))
                .request_async(&self.http)
                .await
                .map_err(|error| ProviderError::Transport(error.to_string()))?;
            let id_token = response.id_token().ok_or(ProviderError::InvalidIdentityToken)?;
            let claims = id_token
                .claims(&self.client.id_token_verifier(), &Nonce::new(nonce))
                .map_err(|_| ProviderError::InvalidIdentityToken)?;
            if self.config.userinfo {
                self.userinfo_identity(
                    response.access_token().clone(),
                    Some(claims.subject().clone()),
                )
                .await
            } else {
                let claims = serde_json::to_value(claims)
                    .map_err(|_| ProviderError::InvalidIdentityToken)?;
                normalize_identity(
                    &self.provider_id,
                    &self.config.issuer,
                    &self.config.identity,
                    &claims,
                    None,
                )
            }
        }
        .instrument(span)
        .await;
        log_provider_result(&self.provider_id, "authorization_code", started, &result);
        result
    }

    async fn authenticate_bearer(
        &self,
        access_token: &str,
        kind: PrincipalKind,
    ) -> Result<ExternalIdentity, ProviderError> {
        let started = std::time::Instant::now();
        tracing::info!(
            event = "authguard.authn.provider.started",
            provider = %self.provider_id,
            flow = "token_exchange",
            "OIDC provider bearer normalization started"
        );
        let span = tracing::info_span!(
            "authn.provider.authenticate",
            otel.kind = "client",
            authguard.provider = %self.provider_id,
            authguard.provider.type = "oidc",
            authguard.provider.flow = "token_exchange",
        );
        let result = async {
            if self.config.token_introspection.is_some() {
                self.introspection_identity(access_token).await
            } else if kind == PrincipalKind::User {
                self.userinfo_identity(
                    openidconnect::AccessToken::new(access_token.to_string()),
                    None,
                )
                .await
            } else {
                Err(ProviderError::UnsupportedFlow)
            }
        }
        .instrument(span)
        .await;
        log_provider_result(&self.provider_id, "token_exchange", started, &result);
        result
    }
}

fn has_accepted_audience(claims: &serde_json::Value, accepted: &[String]) -> bool {
    claims.get("aud").is_some_and(|audience| match audience {
        serde_json::Value::String(value) => accepted.contains(value),
        serde_json::Value::Array(values) => values.iter().any(|value| {
            value.as_str().is_some_and(|value| accepted.iter().any(|item| item == value))
        }),
        _ => false,
    })
}

fn log_provider_result(
    provider: &str,
    flow: &str,
    started: std::time::Instant,
    result: &Result<ExternalIdentity, ProviderError>,
) {
    match result {
        Ok(identity) => tracing::info!(
            event = "authguard.authn.provider.succeeded",
            provider,
            flow,
            subject_present = !identity.subject.is_empty(),
            duration_seconds = started.elapsed().as_secs_f64(),
            "OIDC provider authentication completed"
        ),
        Err(error) => tracing::warn!(
            event = "authguard.authn.provider.failed",
            provider,
            flow,
            error_category = error.category(),
            duration_seconds = started.elapsed().as_secs_f64(),
            "OIDC provider authentication failed"
        ),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::has_accepted_audience;

    #[test]
    fn validates_string_and_array_audiences() {
        let accepted = vec!["customer-growth".to_string()];
        assert!(has_accepted_audience(&json!({"aud": "customer-growth"}), &accepted));
        assert!(has_accepted_audience(&json!({"aud": ["account", "customer-growth"]}), &accepted));
        assert!(!has_accepted_audience(&json!({"aud": "other"}), &accepted));
        assert!(!has_accepted_audience(&json!({}), &accepted));
    }
}
