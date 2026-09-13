//! CAIP-122/SIWX orchestration with high-cohesion chain verifiers.

mod bitcoin;
mod caip;
mod evm;

use std::collections::BTreeMap;
use std::sync::Arc;

use authguard_common::model::{AuthenticationResult, ExternalIdentity, PrincipalKind};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use siwx::{authenticate, AuthOpts, SiwxMessage, Verifier};
use siwx_evm::EvmVerifier;
use siwx_svm::Ed25519Verifier;
use time::OffsetDateTime;

use self::bitcoin::{parse_network, BitcoinVerifier};
use self::caip::CaipAccount;
use self::evm::EvmVerification;
use crate::challenge::{consume_json, put_json, random_challenge_id, ChallengeStore};
use crate::handler::{ApiError, LoginResponse};
use crate::runtime::AuthnRuntime;
use crate::WalletAuthnProperties;

const WALLET_CHALLENGE_PURPOSE: &str = "wallet-siwx";
const WALLET_ISSUER: &str = "caip-122";

#[derive(Clone)]
pub(crate) struct WalletHandler {
    config: WalletAuthnProperties,
    challenges: Arc<dyn ChallengeStore>,
    pipeline: Arc<crate::pipeline::AuthenticationPipeline>,
    evm: EvmVerifier,
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
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WalletVerifyRequest {
    challenge_id: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletChallenge {
    account_id: String,
    namespace: String,
    reference: String,
    nonce: String,
    raw_message: String,
}

impl WalletHandler {
    pub(crate) fn open(runtime: &AuthnRuntime) -> anyhow::Result<Option<Self>> {
        let application = authguard_common::config::AppConfig::get();
        let authn = application.get_authn();
        let config = authn.wallet.clone();
        if !config.enabled {
            return Ok(None);
        }
        let rpc_map = config
            .chains
            .eip155
            .iter()
            .map(|(chain, properties)| Ok((chain.parse::<u64>()?, properties.rpc.clone())))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let evm = EvmVerifier::with_rpc_map(rpc_map).with_rpc_timeout(config.rpc_timeout);
        Ok(Some(Self {
            config,
            challenges: runtime
                .challenges
                .clone()
                .ok_or_else(|| anyhow::anyhow!("wallet AuthN requires Redis challenges"))?,
            pipeline: runtime.pipeline.clone(),
            evm,
            challenge_ttl: authn.challenge_ttl,
        }))
    }

    async fn verify_challenge(
        &self,
        request: WalletVerifyRequest,
    ) -> Result<AuthenticationResult, ApiError> {
        let challenge = consume_json::<WalletChallenge>(
            self.challenges.as_ref(),
            WALLET_CHALLENGE_PURPOSE,
            &request.challenge_id,
        )
        .await
        .map_err(ApiError::challenge)?
        .ok_or_else(|| ApiError::bad_request("invalid or expired wallet challenge"))?;
        let signature = decode_signature(&challenge.namespace, &request.signature)?;
        let max_age = time::Duration::seconds(
            i64::try_from(self.challenge_ttl.as_secs()).unwrap_or(i64::MAX),
        );
        let opts = AuthOpts::new(&self.config.domain, &challenge.nonce)
            .with_uri(&self.config.uri)
            .with_chain_id(&challenge.reference)
            .with_request_id(&request.challenge_id)
            .with_max_issued_age(max_age);
        let method = match challenge.namespace.as_str() {
            "eip155" => {
                EvmVerification { verifier: &self.evm }
                    .verify(&challenge.raw_message, &signature, &opts)
                    .await
            }
            "solana" => {
                authenticate(&Ed25519Verifier::new(), &challenge.raw_message, &signature, &opts)
                    .await
                    .map(|_| "solana")
            }
            "bip122" => {
                let network = self
                    .config
                    .chains
                    .bip122
                    .get(&challenge.reference)
                    .and_then(|chain| parse_network(&chain.network))
                    .ok_or_else(|| ApiError::bad_request("wallet chain is not configured"))?;
                authenticate(
                    &BitcoinVerifier::new(network),
                    &challenge.raw_message,
                    &signature,
                    &opts,
                )
                .await
                .map(|_| "bitcoin")
            }
            _ => return Err(ApiError::bad_request("unsupported CAIP namespace")),
        }
        .map_err(wallet_verification_error)?;
        Ok(AuthenticationResult::new(
            ExternalIdentity {
                provider: "wallet".to_string(),
                issuer: WALLET_ISSUER.to_string(),
                subject: challenge.account_id,
                claims: BTreeMap::new(),
            },
            vec!["wallet".to_string(), "siwx".to_string(), method.to_string()],
            Some("urn:authguard:acr:wallet-possession".to_string()),
            Utc::now(),
        ))
    }

    fn validate_account(&self, account: &CaipAccount) -> Result<&'static str, ApiError> {
        match account.namespace.as_str() {
            "eip155" if self.config.chains.eip155.contains_key(&account.reference) => {
                siwx_evm::validate_address(&account.address).map_err(wallet_verification_error)?;
                Ok("hex")
            }
            "solana" if self.config.chains.solana.contains(&account.reference) => {
                siwx_svm::validate_address(&account.address).map_err(wallet_verification_error)?;
                Ok("base58")
            }
            "bip122" if self.config.chains.bip122.contains_key(&account.reference) => {
                BitcoinVerifier::validate_address(&account.address)
                    .map_err(wallet_verification_error)?;
                Ok("base64")
            }
            "eip155" | "solana" | "bip122" => {
                Err(ApiError::bad_request("wallet chain is not configured"))
            }
            _ => Err(ApiError::bad_request("unsupported CAIP namespace")),
        }
    }
}

pub(crate) async fn challenge(
    State(state): State<WalletHandler>,
    Json(request): Json<WalletChallengeRequest>,
) -> Result<Json<WalletChallengeResponse>, ApiError> {
    let account = CaipAccount::parse(&request.account_id)?;
    let signature_encoding = state.validate_account(&account)?;
    let challenge_id = random_challenge_id();
    let nonce = siwx::nonce::generate_default();
    let now = OffsetDateTime::now_utc();
    let ttl =
        time::Duration::seconds(i64::try_from(state.challenge_ttl.as_secs()).unwrap_or(i64::MAX));
    let mut message = SiwxMessage::new(
        &state.config.domain,
        &account.address,
        &state.config.uri,
        &account.reference,
        &nonce,
    )?;
    if !state.config.statement.is_empty() {
        message = message.with_statement(&state.config.statement)?;
    }
    message = message
        .with_issued_at(now)?
        .with_expiration_time(now + ttl)?
        .with_request_id(&challenge_id)?;
    let raw_message = match account.namespace.as_str() {
        "eip155" => EvmVerifier::format_message(&message),
        "solana" => Ed25519Verifier::format_message(&message),
        "bip122" => BitcoinVerifier::format_message(&message),
        _ => return Err(ApiError::bad_request("unsupported CAIP namespace")),
    };
    put_json(
        state.challenges.as_ref(),
        WALLET_CHALLENGE_PURPOSE,
        &challenge_id,
        &WalletChallenge {
            account_id: account.canonical(),
            namespace: account.namespace,
            reference: account.reference,
            nonce,
            raw_message: raw_message.clone(),
        },
        state.challenge_ttl,
    )
    .await
    .map_err(ApiError::challenge)?;
    Ok(Json(WalletChallengeResponse {
        challenge_id,
        account_id: request.account_id,
        message: raw_message,
        expires_at: (now + ttl).to_string(),
        signature_encoding,
    }))
}

pub(crate) async fn verify(
    State(state): State<WalletHandler>,
    Json(request): Json<WalletVerifyRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let authentication = state.verify_challenge(request).await?;
    let session = state
        .pipeline
        .login(authentication, PrincipalKind::User)
        .await
        .map_err(ApiError::pipeline)?;
    Ok(Json(LoginResponse::new(session, String::new())))
}

pub(crate) async fn link(
    State(state): State<WalletHandler>,
    headers: HeaderMap,
    Json(request): Json<WalletVerifyRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let principal_id = state.pipeline.authenticate_session(&headers).map_err(ApiError::session)?;
    let authentication = state.verify_challenge(request).await?;
    let session =
        state.pipeline.link(&principal_id, authentication).await.map_err(ApiError::pipeline)?;
    Ok(Json(LoginResponse::new(session, String::new())))
}

fn decode_signature(namespace: &str, signature: &str) -> Result<Vec<u8>, ApiError> {
    if signature.len() > 32_768 {
        return Err(ApiError::bad_request("wallet signature is too large"));
    }
    match namespace {
        "eip155" => hex::decode(signature.strip_prefix("0x").unwrap_or(signature))
            .map_err(|_| ApiError::bad_request("wallet signature encoding is invalid")),
        "solana" => bs58::decode(signature)
            .into_vec()
            .map_err(|_| ApiError::bad_request("wallet signature encoding is invalid")),
        "bip122" => STANDARD
            .decode(signature)
            .map_err(|_| ApiError::bad_request("wallet signature encoding is invalid")),
        _ => Err(ApiError::bad_request("unsupported CAIP namespace")),
    }
}

fn wallet_verification_error(error: siwx::SiwxError) -> ApiError {
    tracing::warn!(error = %error, "SIWX wallet proof rejected");
    let response = match &error {
        siwx::SiwxError::Backend { .. } => {
            ApiError::unavailable("wallet verification service is unavailable")
        }
        _ => ApiError::unauthorized("wallet signature verification failed"),
    };
    drop(error);
    response
}

impl From<siwx::SiwxError> for ApiError {
    fn from(error: siwx::SiwxError) -> Self {
        wallet_verification_error(error)
    }
}
