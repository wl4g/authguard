use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crate::{
    AccountLinkingError, AuthnFlowRepository, AuthnProperties, GithubOauth2Provider,
    GoogleOauth2Provider, IProviderAdapter, IamAuthFlowInfo, IdentityBindingRepository,
    JitPrincipalDiscovery, OAuthLikeCallback, OAuthLikeProvider, PrincipalKind, ProviderProperties,
    QqOauth2Provider, ReqwestProviderTransport, WechatOauth2Provider,
};
use anyhow::Context as _;
use authguard_common::apm::AuthnMetrics;
use authguard_common::utils::jwt::{load_signing_key, sign, JwtSigningKey};
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

#[derive(Clone)]
struct ProviderRuntime {
    adapter: Arc<dyn IProviderAdapter>,
    client_id: String,
    client_secret: String,
    callback_url: String,
}

#[derive(Clone)]
pub(crate) struct AuthenticationHandler {
    providers: Arc<BTreeMap<String, ProviderRuntime>>,
    flows: Arc<dyn AuthnFlowRepository>,
    identities: Arc<dyn IdentityBindingRepository>,
    linking: crate::AccountLinkingProperties,
    session: crate::SessionProperties,
    signing_key: Option<JwtSigningKey>,
    metrics: AuthnMetrics,
}

#[derive(Deserialize)]
pub(crate) struct AuthorizeQuery {
    #[serde(default)]
    return_uri: String,
}

#[derive(Deserialize)]
pub(crate) struct CallbackQuery {
    code: String,
    state: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    return_uri: String,
    principal: authguard_common::AuthenticatedPrincipalContext,
}

impl AuthenticationHandler {
    pub(crate) async fn open(metrics: AuthnMetrics) -> anyhow::Result<Self> {
        let config = authguard_common::config::AppConfig::get();
        let storage = config.get_storage();
        let (flows, identities): (
            Arc<dyn AuthnFlowRepository>,
            Arc<dyn IdentityBindingRepository>,
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
        let providers = build_providers(config.get_authn())?;
        let signing_key = load_session_key(config.get_authn(), providers.is_empty())?;
        tracing::info!(
            provider_count = providers.len(),
            linking_strategy = ?config.authn.account_linking.strategy,
            storage_provider = %config.storage.provider,
            "AuthGuard AuthN provider engine configured"
        );
        Ok(Self {
            providers: Arc::new(providers),
            flows,
            identities,
            linking: config.authn.account_linking.clone(),
            session: config.authn.session.clone(),
            signing_key,
            metrics,
        })
    }
}

pub(crate) async fn authorize(
    AxumPath(provider): AxumPath<String>,
    Query(query): Query<AuthorizeQuery>,
    State(state): State<AuthenticationHandler>,
) -> Result<Redirect, ApiError> {
    let started = Instant::now();
    tracing::info!(
        event = "authguard.authn.authorize.started",
        provider,
        "social authentication authorize request received"
    );
    let result = async {
        let runtime =
            state.providers.get(&provider).ok_or_else(|| ApiError::invalid_provider(&provider))?;
        let state_value = random_state();
        let expires_at_epoch_seconds =
            epoch_seconds().saturating_add(state.session.state_ttl.as_secs());
        state
            .flows
            .create(
                &state_hash(&state_value),
                &IamAuthFlowInfo {
                    provider: provider.clone(),
                    return_uri: query.return_uri,
                    expires_at_epoch_seconds,
                },
            )
            .await
            .map_err(ApiError::storage)?;
        let url = runtime
            .adapter
            .authorization_url(&runtime.client_id, &runtime.callback_url, &state_value)
            .map_err(ApiError::provider)?;
        Ok(Redirect::temporary(url.as_str()))
    }
    .await;
    let outcome = result.as_ref().err().map_or("success", ApiError::metric_outcome);
    state.metrics.record_flow(&provider, "authorize", outcome, started.elapsed().as_secs_f64());
    match &result {
        Ok(_) => tracing::info!(
            event = "authguard.authn.authorize.succeeded",
            provider,
            duration_seconds = started.elapsed().as_secs_f64(),
            "social authentication authorize redirect prepared"
        ),
        Err(error) => tracing::warn!(
            event = "authguard.authn.authorize.failed",
            provider,
            error_code = error.code,
            duration_seconds = started.elapsed().as_secs_f64(),
            "social authentication authorize request failed"
        ),
    }
    result
}

pub(crate) async fn callback(
    AxumPath(provider): AxumPath<String>,
    Query(query): Query<CallbackQuery>,
    State(state): State<AuthenticationHandler>,
) -> Result<Json<LoginResponse>, ApiError> {
    let started = Instant::now();
    tracing::info!(
        event = "authguard.authn.callback.started",
        provider,
        "social IdP callback received"
    );
    let result = async {
        let flow = state
            .flows
            .consume(&state_hash(&query.state))
            .await
            .map_err(ApiError::storage)?
            .filter(|flow| {
                flow.provider == provider && flow.expires_at_epoch_seconds > epoch_seconds()
            })
            .ok_or_else(|| ApiError::invalid_request("invalid or expired OAuth state"))?;
        let runtime =
            state.providers.get(&provider).ok_or_else(|| ApiError::invalid_provider(&provider))?;
        let identity = runtime
            .adapter
            .authenticate(OAuthLikeCallback {
                authorization_code: query.code,
                redirect_uri: runtime.callback_url.clone(),
                client_id: runtime.client_id.clone(),
                client_secret: runtime.client_secret.clone(),
            })
            .await
            .map_err(ApiError::provider)?;
        let principal = JitPrincipalDiscovery::new(state.linking.clone(), state.identities.clone())
            .discover(&identity, PrincipalKind::User)
            .await
            .map_err(ApiError::linking)?;
        let access_token = issue_token(
            state.signing_key.as_ref().ok_or_else(ApiError::signing_unavailable)?,
            &state.session,
            &principal,
        )?;
        Ok(Json(LoginResponse {
            access_token,
            token_type: "Bearer",
            expires_in: state.session.ttl.as_secs(),
            return_uri: flow.return_uri,
            principal,
        }))
    }
    .await;
    let outcome = result.as_ref().err().map_or("success", ApiError::metric_outcome);
    state.metrics.record_flow(&provider, "callback", outcome, started.elapsed().as_secs_f64());
    match &result {
        Ok(response) => tracing::info!(
            event = "authguard.authn.callback.succeeded",
            provider,
            principal_id = %response.0.principal.principal_id,
            duration_seconds = started.elapsed().as_secs_f64(),
            "social IdP callback normalized and linked"
        ),
        Err(error) => tracing::warn!(
            event = "authguard.authn.callback.failed",
            provider,
            error_code = error.code,
            duration_seconds = started.elapsed().as_secs_f64(),
            "social IdP callback failed closed"
        ),
    }
    result
}

fn build_providers(config: &AuthnProperties) -> anyhow::Result<BTreeMap<String, ProviderRuntime>> {
    let transport = ReqwestProviderTransport::new(Duration::from_secs(10))?;
    config
        .providers
        .iter()
        .map(|(provider, config)| {
            let oauth = match config {
                ProviderProperties::OAuth2(config) | ProviderProperties::OAuth2Like(config) => {
                    config
                }
                ProviderProperties::Custom(_) => anyhow::bail!(
                    "custom provider `{provider}` requires a registered Provider SPI adapter"
                ),
            };
            if oauth.client_id.is_empty()
                || oauth.client_secret.is_empty()
                || oauth.callback_url.is_empty()
            {
                anyhow::bail!("provider `{provider}` requires clientId, clientSecret, callbackUrl");
            }
            let adapter: Arc<dyn IProviderAdapter> = match provider.as_str() {
                "github" => Arc::new(GithubOauth2Provider::new(oauth.clone(), transport.clone())?),
                "google" => Arc::new(GoogleOauth2Provider::new(oauth.clone(), transport.clone())?),
                "qq" => Arc::new(QqOauth2Provider::new(oauth.clone(), transport.clone())?),
                "wechat" => Arc::new(WechatOauth2Provider::new(oauth.clone(), transport.clone())?),
                _ => Arc::new(OAuthLikeProvider::new(
                    provider.clone(),
                    oauth.clone(),
                    transport.clone(),
                )?),
            };
            Ok((
                provider.clone(),
                ProviderRuntime {
                    adapter,
                    client_id: oauth.client_id.clone(),
                    client_secret: oauth.client_secret.clone(),
                    callback_url: oauth.callback_url.clone(),
                },
            ))
        })
        .collect()
}

fn load_session_key(
    config: &AuthnProperties,
    providers_empty: bool,
) -> anyhow::Result<Option<JwtSigningKey>> {
    let key = if config.session.private_key_file.is_empty() {
        config.session.private_key.clone()
    } else {
        std::fs::read_to_string(&config.session.private_key_file)
            .context("read AuthN session private key")?
    };
    if key.is_empty() && providers_empty {
        return Ok(None);
    }
    if key.is_empty() {
        anyhow::bail!(
            "authn.session privateKey or privateKeyFile is required when providers exist"
        );
    }
    Ok(Some(load_signing_key(&key)?))
}

fn issue_token(
    key: &JwtSigningKey,
    session: &crate::SessionProperties,
    principal: &authguard_common::AuthenticatedPrincipalContext,
) -> Result<String, ApiError> {
    let now = epoch_seconds();
    let mut claims = serde_json::Map::from_iter([
        ("iss".to_string(), json!(session.issuer)),
        ("aud".to_string(), json!(session.audience)),
        ("sub".to_string(), json!(principal.principal_id)),
        ("principal_id".to_string(), json!(principal.principal_id)),
        ("principal_kind".to_string(), json!(principal.kind.as_str())),
        ("authguard_group_ids".to_string(), json!(principal.stable_group_ids)),
        ("amr".to_string(), json!(principal.amr)),
        ("iat".to_string(), json!(now)),
        ("exp".to_string(), json!(now.saturating_add(session.ttl.as_secs()))),
    ]);
    if let Some(acr) = &principal.acr {
        claims.insert("acr".to_string(), json!(acr));
    }
    for (name, value) in &principal.trusted_claims {
        claims.insert(name.clone(), json!(value));
    }
    let payload =
        serde_json::to_vec(&Value::Object(claims)).map_err(|_| ApiError::signing_unavailable())?;
    sign(key, &payload).map_err(|_| ApiError::signing_unavailable())
}

fn random_state() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn state_hash(state: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(state.as_bytes()))
}

fn epoch_seconds() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub(crate) struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    fn metric_outcome(&self) -> &'static str {
        match self.code {
            "unknown_provider" | "invalid_request" => "invalid_request",
            "provider_authentication_failed" => "provider_error",
            "account_linking_failed" => "linking_rejected",
            "authn_storage_unavailable" => "storage_error",
            _ => "other",
        }
    }

    fn invalid_provider(_provider: &str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "unknown_provider",
            message: "authentication provider is not configured",
        }
    }

    const fn invalid_request(message: &'static str) -> Self {
        Self { status: StatusCode::BAD_REQUEST, code: "invalid_request", message }
    }

    fn provider(error: crate::ProviderError) -> Self {
        tracing::warn!(error_category = error.category(), "provider authentication failed");
        drop(error);
        Self {
            status: StatusCode::BAD_GATEWAY,
            code: "provider_authentication_failed",
            message: "external identity provider authentication failed",
        }
    }

    fn linking(error: AccountLinkingError) -> Self {
        tracing::warn!(error = %error, "account linking failed closed");
        let status = match &error {
            AccountLinkingError::AuthoritativeLoginRequired { .. }
            | AccountLinkingError::LinkNotAllowed { .. }
            | AccountLinkingError::PrincipalDisabled(_) => StatusCode::FORBIDDEN,
            AccountLinkingError::IdentityAlreadyBound => StatusCode::CONFLICT,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        drop(error);
        Self { status, code: "account_linking_failed", message: "account linking failed" }
    }

    fn storage(error: crate::storage::AuthnFlowRepositoryError) -> Self {
        tracing::error!(error = %error, "AuthN storage operation failed");
        drop(error);
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "authn_storage_unavailable",
            message: "authentication state is temporarily unavailable",
        }
    }

    const fn signing_unavailable() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "session_signing_unavailable",
            message: "canonical session token could not be issued",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"code": self.code, "message": self.message}))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_state_is_stored_only_as_a_hash() {
        assert_ne!(state_hash("secret-state"), "secret-state");
        assert_eq!(state_hash("secret-state"), state_hash("secret-state"));
    }
}
