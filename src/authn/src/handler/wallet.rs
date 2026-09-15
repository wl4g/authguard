//! HTTP and cache orchestration for CAIP/SIWX wallet authentication.

use std::sync::Arc;

use authguard_common::cache::ICache;
use authguard_common::model::PrincipalKind;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::authentication::challenge::{consume_json, put_json};
use crate::authentication::random_id;
use crate::provider::wallet::WalletVerificationMethod;
use crate::provider::wallet::{WalletChallenge, WalletProvider, WalletProviderError};

use super::{ApiError, AuthenticationPipeline, AuthnRuntime, LoginResponse};

#[derive(Clone)]
pub(crate) struct WalletHandler {
    provider: WalletProvider,
    challenges: Arc<dyn ICache>,
    pipeline: Arc<AuthenticationPipeline>,
    challenge_ttl: std::time::Duration,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WalletChallengeRequest {
    account_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WalletChallengeResponse {
    challenge_id: String,
    account_id: String,
    message: String,
    expires_at: String,
    signature_encoding: &'static str,
    verification_methods: Vec<&'static str>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WalletVerifyRequest {
    challenge_id: String,
    signature: String,
    #[serde(default)]
    verification_method: WalletVerificationMethod,
}

impl WalletHandler {
    pub(crate) fn open(runtime: &AuthnRuntime) -> anyhow::Result<Option<Self>> {
        let application = authguard_common::config::AppConfig::get();
        let authn = application.get_authn();
        if !authn.wallet.enabled {
            return Ok(None);
        }
        Ok(Some(Self {
            provider: WalletProvider::new(authn.wallet.clone(), authn.challenge_ttl)?,
            challenges: runtime
                .challenges
                .clone()
                .ok_or_else(|| anyhow::anyhow!("wallet AuthN requires the challenge cache"))?,
            pipeline: runtime.pipeline.clone(),
            challenge_ttl: authn.challenge_ttl,
        }))
    }

    async fn verify_challenge(
        &self,
        request: WalletVerifyRequest,
    ) -> Result<authguard_common::model::AuthenticationResult, ApiError> {
        let challenge = consume_json::<WalletChallenge>(
            self.challenges.as_ref(),
            WalletProvider::CHALLENGE_PURPOSE,
            &request.challenge_id,
        )
        .await
        .map_err(ApiError::challenge)?
        .ok_or_else(|| ApiError::bad_request("invalid or expired wallet challenge"))?;
        self.provider
            .verify(
                challenge,
                &request.challenge_id,
                &request.signature,
                request.verification_method,
            )
            .await
            .map_err(wallet_error)
    }
}

pub(crate) async fn challenge(
    State(state): State<WalletHandler>,
    Json(request): Json<WalletChallengeRequest>,
) -> Result<Json<WalletChallengeResponse>, ApiError> {
    let challenge_id = random_id();
    let prepared = state
        .provider
        .prepare_challenge(&request.account_id, &challenge_id)
        .map_err(wallet_error)?;
    put_json(
        state.challenges.as_ref(),
        WalletProvider::CHALLENGE_PURPOSE,
        &challenge_id,
        &prepared.state,
        state.challenge_ttl,
    )
    .await
    .map_err(ApiError::challenge)?;
    Ok(Json(WalletChallengeResponse {
        challenge_id,
        account_id: prepared.account_id,
        message: prepared.message,
        expires_at: prepared.expires_at,
        signature_encoding: prepared.signature_encoding,
        verification_methods: prepared.verification_methods,
    }))
}

pub(crate) async fn verify(
    State(state): State<WalletHandler>,
    Json(request): Json<WalletVerifyRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let authentication = state.verify_challenge(request).await?;
    let issued = state
        .pipeline
        .login(authentication, PrincipalKind::User)
        .await
        .map_err(ApiError::pipeline)?;
    Ok(Json(LoginResponse::new(issued, String::new())))
}

pub(crate) async fn link(
    State(state): State<WalletHandler>,
    headers: HeaderMap,
    Json(request): Json<WalletVerifyRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let principal_id = state.pipeline.authenticate_token(&headers).map_err(ApiError::token)?;
    let authentication = state.verify_challenge(request).await?;
    let issued =
        state.pipeline.link(&principal_id, authentication).await.map_err(ApiError::pipeline)?;
    Ok(Json(LoginResponse::new(issued, String::new())))
}

fn wallet_error(error: WalletProviderError) -> ApiError {
    match error {
        WalletProviderError::InvalidAccount => ApiError::bad_request("invalid CAIP-10 account id"),
        WalletProviderError::ChainNotConfigured => {
            ApiError::bad_request("wallet chain is not configured")
        }
        WalletProviderError::UnsupportedNamespace => {
            ApiError::bad_request("unsupported CAIP namespace")
        }
        WalletProviderError::SignatureTooLarge => {
            ApiError::bad_request("wallet signature is too large")
        }
        WalletProviderError::InvalidSignatureEncoding => {
            ApiError::bad_request("wallet signature encoding is invalid")
        }
        WalletProviderError::Backend => {
            ApiError::unavailable("wallet verification service is unavailable")
        }
        WalletProviderError::ContractVerificationNotConfigured => ApiError::not_implemented(
            "contract_wallet_not_supported",
            "contract-wallet verification is not configured for this chain",
        ),
        WalletProviderError::VerificationMethodMismatch => {
            ApiError::unauthorized("wallet verification method does not match the proof")
        }
        WalletProviderError::Verification => {
            ApiError::unauthorized("wallet signature verification failed")
        }
    }
}
