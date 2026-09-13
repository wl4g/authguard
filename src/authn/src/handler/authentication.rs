//! OAuth/OIDC protocol adapter. It converges only after proof verification.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use authguard_common::apm::AuthnMetrics;
use authguard_common::model::{AuthenticationResult, ExternalIdentity, PrincipalKind};
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::HeaderMap;
use axum::response::Redirect;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::challenge::{consume_json, put_json, random_challenge_id, ChallengeStore};
use crate::handler::{ApiError, LoginResponse};
use crate::runtime::AuthnRuntime;
use crate::{
    AuthnProperties, GithubOauth2Provider, GoogleOauth2Provider, IProviderAdapter,
    OAuthLikeCallback, OAuthLikeProvider, OidcProvider, ProviderProperties, QqOauth2Provider,
    ReqwestProviderTransport, WechatOauth2Provider,
};

const OAUTH_CHALLENGE_PURPOSE: &str = "oauth";

#[derive(Clone)]
struct ProviderRuntime {
    adapter: Arc<dyn IProviderAdapter>,
    client_id: String,
    client_secret: String,
    callback_url: String,
    protocol: ProviderProtocol,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
enum ProviderProtocol {
    OAuth2,
    Oidc,
}

#[derive(Clone)]
pub(crate) struct AuthenticationHandler {
    providers: Arc<BTreeMap<String, ProviderRuntime>>,
    challenges: Arc<dyn ChallengeStore>,
    pipeline: Arc<crate::pipeline::AuthenticationPipeline>,
    challenge_ttl: Duration,
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TokenExchangeRequest {
    subject_token: String,
    kind: PrincipalKind,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OAuthChallenge {
    provider: String,
    return_uri: String,
    nonce: Option<String>,
    pkce_verifier: Option<String>,
    link_principal_id: Option<String>,
}

impl AuthenticationHandler {
    pub(crate) async fn open(
        metrics: AuthnMetrics,
        runtime: &AuthnRuntime,
    ) -> anyhow::Result<Option<Self>> {
        let application = authguard_common::config::AppConfig::get();
        let config = application.get_authn();
        let providers = build_providers(config).await?;
        if providers.is_empty() {
            return Ok(None);
        }
        let challenges = runtime
            .challenges
            .clone()
            .ok_or_else(|| anyhow::anyhow!("OAuth providers require the Redis challenge store"))?;
        tracing::info!(
            provider_count = providers.len(),
            "OAuth/OIDC authentication adapters configured"
        );
        Ok(Some(Self {
            providers: Arc::new(providers),
            challenges,
            pipeline: runtime.pipeline.clone(),
            challenge_ttl: config.challenge_ttl,
            metrics,
        }))
    }
}

pub(crate) async fn authorize(
    AxumPath(provider): AxumPath<String>,
    Query(query): Query<AuthorizeQuery>,
    State(state): State<AuthenticationHandler>,
) -> Result<Redirect, ApiError> {
    prepare_authorization(&state, &provider, query.return_uri, None).await
}

pub(crate) async fn link_authorize(
    AxumPath(provider): AxumPath<String>,
    Query(query): Query<AuthorizeQuery>,
    State(state): State<AuthenticationHandler>,
    headers: HeaderMap,
) -> Result<Redirect, ApiError> {
    let principal_id = state.pipeline.authenticate_session(&headers).map_err(ApiError::session)?;
    prepare_authorization(&state, &provider, query.return_uri, Some(principal_id)).await
}

async fn prepare_authorization(
    state: &AuthenticationHandler,
    provider: &str,
    return_uri: String,
    link_principal_id: Option<String>,
) -> Result<Redirect, ApiError> {
    let started = Instant::now();
    let result = async {
        let runtime = state
            .providers
            .get(provider)
            .ok_or_else(|| ApiError::not_found("authentication provider is not configured"))?;
        let state_value = random_challenge_id();
        let authorization = runtime
            .adapter
            .authorize(&runtime.client_id, &runtime.callback_url, &state_value)
            .map_err(provider_error)?;
        put_json(
            state.challenges.as_ref(),
            OAUTH_CHALLENGE_PURPOSE,
            &state_value,
            &OAuthChallenge {
                provider: provider.to_string(),
                return_uri,
                nonce: authorization.nonce,
                pkce_verifier: authorization.pkce_verifier,
                link_principal_id,
            },
            state.challenge_ttl,
        )
        .await
        .map_err(ApiError::challenge)?;
        Ok(Redirect::temporary(authorization.url.as_str()))
    }
    .await;
    let outcome = result.as_ref().err().map_or("success", ApiError::metric_outcome);
    state.metrics.record_flow(provider, "authorize", outcome, started.elapsed().as_secs_f64());
    result
}

pub(crate) async fn callback(
    AxumPath(provider): AxumPath<String>,
    Query(query): Query<CallbackQuery>,
    State(state): State<AuthenticationHandler>,
) -> Result<Json<LoginResponse>, ApiError> {
    let started = Instant::now();
    let result = async {
        let flow = consume_json::<OAuthChallenge>(
            state.challenges.as_ref(),
            OAUTH_CHALLENGE_PURPOSE,
            &query.state,
        )
        .await
        .map_err(ApiError::challenge)?
        .filter(|flow| flow.provider == provider)
        .ok_or_else(|| ApiError::bad_request("invalid or expired OAuth state"))?;
        let runtime = state
            .providers
            .get(&provider)
            .ok_or_else(|| ApiError::not_found("authentication provider is not configured"))?;
        let identity = runtime
            .adapter
            .authenticate(OAuthLikeCallback {
                authorization_code: query.code,
                redirect_uri: runtime.callback_url.clone(),
                client_id: runtime.client_id.clone(),
                client_secret: runtime.client_secret.clone(),
                nonce: flow.nonce,
                pkce_verifier: flow.pkce_verifier,
            })
            .await
            .map_err(provider_error)?;
        let authentication = provider_authentication(identity, runtime.protocol);
        let session = if let Some(principal_id) = flow.link_principal_id {
            state.pipeline.link(&principal_id, authentication).await
        } else {
            state.pipeline.login(authentication, PrincipalKind::User).await
        }
        .map_err(ApiError::pipeline)?;
        Ok(Json(LoginResponse::new(session, flow.return_uri)))
    }
    .await;
    let outcome = result.as_ref().err().map_or("success", ApiError::metric_outcome);
    state.metrics.record_flow(&provider, "callback", outcome, started.elapsed().as_secs_f64());
    result
}

pub(crate) async fn token_exchange(
    AxumPath(provider): AxumPath<String>,
    State(state): State<AuthenticationHandler>,
    Json(request): Json<TokenExchangeRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let started = Instant::now();
    let result = async {
        if request.subject_token.is_empty() {
            return Err(ApiError::bad_request("subjectToken is required"));
        }
        if request.kind == PrincipalKind::Group {
            return Err(ApiError::bad_request(
                "GROUP principals cannot authenticate with bearer tokens",
            ));
        }
        let runtime = state
            .providers
            .get(&provider)
            .ok_or_else(|| ApiError::not_found("authentication provider is not configured"))?;
        let identity = runtime
            .adapter
            .authenticate_bearer(&request.subject_token, request.kind)
            .await
            .map_err(provider_error)?;
        let authentication = provider_authentication(identity, runtime.protocol);
        let session =
            state.pipeline.login(authentication, request.kind).await.map_err(ApiError::pipeline)?;
        Ok(Json(LoginResponse::new(session, String::new())))
    }
    .await;
    let outcome = result.as_ref().err().map_or("success", ApiError::metric_outcome);
    state.metrics.record_flow(
        &provider,
        "token_exchange",
        outcome,
        started.elapsed().as_secs_f64(),
    );
    result
}

fn provider_authentication(
    mut identity: ExternalIdentity,
    protocol: ProviderProtocol,
) -> AuthenticationResult {
    // Authentication evidence is transient and must not remain attached to
    // the durable external-identity description.
    let method_claim = identity.claims.remove("amr");
    let assurance_claim = identity.claims.remove("acr");
    let (fallback, acr) = match protocol {
        ProviderProtocol::OAuth2 => (vec!["oauth2".to_string()], None),
        ProviderProtocol::Oidc => {
            let amr = method_claim
                .as_ref()
                .and_then(serde_json::Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .filter(|value| !value.is_empty() && value.len() <= 64)
                        .take(16)
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .filter(|values| !values.is_empty())
                .unwrap_or_else(|| vec!["oidc".to_string()]);
            let acr = assurance_claim
                .as_ref()
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 512)
                .map(str::to_string);
            (amr, acr)
        }
    };
    AuthenticationResult::new(identity, fallback, acr, Utc::now())
}

fn provider_error(error: crate::ProviderError) -> ApiError {
    tracing::warn!(error_category = error.category(), "provider authentication failed");
    drop(error);
    ApiError::unavailable("external identity provider authentication failed")
}

async fn build_providers(
    config: &AuthnProperties,
) -> anyhow::Result<BTreeMap<String, ProviderRuntime>> {
    let transport = ReqwestProviderTransport::new(Duration::from_secs(10))?;
    let mut providers = BTreeMap::new();
    for (provider, properties) in &config.providers {
        let runtime = match properties {
            ProviderProperties::Oidc(oidc) => {
                validate_oidc_provider(
                    provider,
                    &oidc.issuer,
                    &oidc.client_id,
                    &oidc.callback_url,
                )?;
                ProviderRuntime {
                    adapter: Arc::new(OidcProvider::discover(provider, oidc.clone()).await?),
                    client_id: oidc.client_id.clone(),
                    client_secret: oidc.client_secret.clone(),
                    callback_url: oidc.callback_url.clone(),
                    protocol: ProviderProtocol::Oidc,
                }
            }
            ProviderProperties::OAuth2(oauth) | ProviderProperties::OAuth2Like(oauth) => {
                validate_provider_credentials(
                    provider,
                    &oauth.client_id,
                    &oauth.client_secret,
                    &oauth.callback_url,
                )?;
                let adapter: Arc<dyn IProviderAdapter> = match provider.as_str() {
                    "github" => {
                        Arc::new(GithubOauth2Provider::new(oauth.clone(), transport.clone())?)
                    }
                    "google" => {
                        Arc::new(GoogleOauth2Provider::new(oauth.clone(), transport.clone())?)
                    }
                    "qq" => Arc::new(QqOauth2Provider::new(oauth.clone(), transport.clone())?),
                    "wechat" => {
                        Arc::new(WechatOauth2Provider::new(oauth.clone(), transport.clone())?)
                    }
                    _ => Arc::new(OAuthLikeProvider::new(
                        provider.clone(),
                        oauth.clone(),
                        transport.clone(),
                    )?),
                };
                ProviderRuntime {
                    adapter,
                    client_id: oauth.client_id.clone(),
                    client_secret: oauth.client_secret.clone(),
                    callback_url: oauth.callback_url.clone(),
                    protocol: ProviderProtocol::OAuth2,
                }
            }
            ProviderProperties::Custom(_) => anyhow::bail!(
                "custom provider `{provider}` requires a registered Provider SPI adapter"
            ),
        };
        providers.insert(provider.clone(), runtime);
    }
    Ok(providers)
}

fn validate_provider_credentials(
    provider: &str,
    client_id: &str,
    client_secret: &str,
    callback_url: &str,
) -> anyhow::Result<()> {
    if client_id.is_empty() || client_secret.is_empty() || callback_url.is_empty() {
        anyhow::bail!("provider `{provider}` requires clientId, clientSecret, callbackUrl");
    }
    Ok(())
}

fn validate_oidc_provider(
    provider: &str,
    issuer: &str,
    client_id: &str,
    callback_url: &str,
) -> anyhow::Result<()> {
    if issuer.is_empty() || client_id.is_empty() || callback_url.is_empty() {
        anyhow::bail!("OIDC provider `{provider}` requires issuer, clientId, callbackUrl");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;

    #[test]
    fn oidc_authentication_preserves_the_actual_evidence() {
        let authentication = provider_authentication(
            ExternalIdentity {
                provider: "corporate".to_string(),
                issuer: "https://id.example".to_string(),
                subject: "123".to_string(),
                claims: BTreeMap::from([
                    ("amr".to_string(), json!(["pwd", "otp"])),
                    ("acr".to_string(), json!("urn:example:mfa")),
                ]),
            },
            ProviderProtocol::Oidc,
        );
        assert_eq!(authentication.amr, ["pwd", "otp"]);
        assert_eq!(authentication.acr.as_deref(), Some("urn:example:mfa"));
        assert!(!authentication.external_identity.claims.contains_key("amr"));
        assert!(!authentication.external_identity.claims.contains_key("acr"));
    }
}
