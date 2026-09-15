//! CAIP-122/SIWX protocol orchestration with high-cohesion chain verifiers.

mod bitcoin;
mod caip;
mod evm;

use std::collections::BTreeMap;

use authguard_common::model::{AuthenticationResult, ExternalIdentity};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use siwx::{authenticate, AuthOpts, SiwxMessage, Verifier};
use siwx_evm::EvmVerifier;
use siwx_svm::Ed25519Verifier;
use thiserror::Error;
use time::OffsetDateTime;

use self::bitcoin::{parse_network, BitcoinVerifier};
use self::caip::CaipAccount;
use self::evm::{EvmVerification, EvmVerificationError};
use crate::WalletAuthnProperties;

const WALLET_ISSUER: &str = "caip-122";

#[derive(Clone)]
pub(crate) struct WalletProvider {
    config: WalletAuthnProperties,
    evm: EvmVerifier,
    challenge_ttl: std::time::Duration,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WalletChallenge {
    account_id: String,
    namespace: String,
    reference: String,
    nonce: String,
    raw_message: String,
}

pub(crate) struct PreparedWalletChallenge {
    pub account_id: String,
    pub message: String,
    pub expires_at: String,
    pub signature_encoding: &'static str,
    pub verification_methods: Vec<&'static str>,
    pub state: WalletChallenge,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum WalletVerificationMethod {
    #[default]
    Auto,
    Eoa,
    Erc1271,
    Erc6492,
}

#[derive(Clone, Copy, Debug, Error)]
pub(crate) enum WalletProviderError {
    #[error("invalid CAIP-10 account id")]
    InvalidAccount,
    #[error("wallet chain is not configured")]
    ChainNotConfigured,
    #[error("unsupported CAIP namespace")]
    UnsupportedNamespace,
    #[error("wallet signature is too large")]
    SignatureTooLarge,
    #[error("wallet signature encoding is invalid")]
    InvalidSignatureEncoding,
    #[error("wallet verification backend is unavailable")]
    Backend,
    #[error("contract-wallet verification is not configured for this chain")]
    ContractVerificationNotConfigured,
    #[error("wallet verification method does not match the proof")]
    VerificationMethodMismatch,
    #[error("wallet proof verification failed")]
    Verification,
}

impl WalletProvider {
    pub(crate) const CHALLENGE_PURPOSE: &'static str = "wallet-siwx";

    pub(crate) fn new(
        config: WalletAuthnProperties,
        challenge_ttl: std::time::Duration,
    ) -> anyhow::Result<Self> {
        let rpc_map = config
            .chains
            .eip155
            .iter()
            .filter_map(|(chain, properties)| {
                properties.rpc.as_ref().map(|rpc| Ok((chain.parse::<u64>()?, rpc.clone())))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let evm = EvmVerifier::with_rpc_map(rpc_map).with_rpc_timeout(config.rpc_timeout);
        Ok(Self { config, evm, challenge_ttl })
    }

    pub(crate) fn prepare_challenge(
        &self,
        account_id: &str,
        challenge_id: &str,
    ) -> Result<PreparedWalletChallenge, WalletProviderError> {
        let account = CaipAccount::parse(account_id)?;
        let signature_encoding = self.validate_account(&account)?;
        let verification_methods = self.verification_methods(&account);
        let account_id = account.canonical();
        let nonce = siwx::nonce::generate_default();
        let now = OffsetDateTime::now_utc();
        let ttl = time::Duration::seconds(
            i64::try_from(self.challenge_ttl.as_secs()).unwrap_or(i64::MAX),
        );
        let mut message = SiwxMessage::new(
            &self.config.domain,
            &account.address,
            &self.config.uri,
            &account.reference,
            &nonce,
        )
        .map_err(protocol_error)?;
        if !self.config.statement.is_empty() {
            message = message.with_statement(&self.config.statement).map_err(protocol_error)?;
        }
        let expires_at = now + ttl;
        message = message
            .with_issued_at(now)
            .and_then(|message| message.with_expiration_time(expires_at))
            .and_then(|message| message.with_request_id(challenge_id))
            .map_err(protocol_error)?;
        let raw_message = match account.namespace.as_str() {
            "eip155" => EvmVerifier::format_message(&message),
            "solana" => Ed25519Verifier::format_message(&message),
            "bip122" => BitcoinVerifier::format_message(&message),
            _ => return Err(WalletProviderError::UnsupportedNamespace),
        };
        Ok(PreparedWalletChallenge {
            account_id: account_id.clone(),
            message: raw_message.clone(),
            expires_at: chrono::DateTime::<Utc>::from_timestamp(
                expires_at.unix_timestamp(),
                expires_at.nanosecond(),
            )
            .ok_or(WalletProviderError::Backend)?
            .to_rfc3339_opts(SecondsFormat::Nanos, true),
            signature_encoding,
            verification_methods,
            state: WalletChallenge {
                account_id,
                namespace: account.namespace,
                reference: account.reference,
                nonce,
                raw_message,
            },
        })
    }

    pub(crate) async fn verify(
        &self,
        challenge: WalletChallenge,
        challenge_id: &str,
        signature: &str,
        requested_method: WalletVerificationMethod,
    ) -> Result<AuthenticationResult, WalletProviderError> {
        let signature = decode_signature(&challenge.namespace, signature)?;
        let max_age = time::Duration::seconds(
            i64::try_from(self.challenge_ttl.as_secs()).unwrap_or(i64::MAX),
        );
        let opts = AuthOpts::new(&self.config.domain, &challenge.nonce)
            .with_uri(&self.config.uri)
            .with_chain_id(&challenge.reference)
            .with_request_id(challenge_id)
            .with_max_issued_age(max_age);
        let method = match challenge.namespace.as_str() {
            "eip155" => {
                let contract_verifier = self
                    .config
                    .chains
                    .eip155
                    .get(&challenge.reference)
                    .and_then(|chain| chain.rpc.as_ref())
                    .map(|_| &self.evm);
                EvmVerification { contract_verifier }
                    .verify(&challenge.raw_message, &signature, &opts, requested_method)
                    .await
                    .map_err(evm_error)
            }
            "solana" => {
                if requested_method != WalletVerificationMethod::Auto {
                    return Err(WalletProviderError::VerificationMethodMismatch);
                }
                authenticate(&Ed25519Verifier::new(), &challenge.raw_message, &signature, &opts)
                    .await
                    .map(|_| "solana")
                    .map_err(verification_error)
            }
            "bip122" => {
                if requested_method != WalletVerificationMethod::Auto {
                    return Err(WalletProviderError::VerificationMethodMismatch);
                }
                let network = self
                    .config
                    .chains
                    .bip122
                    .get(&challenge.reference)
                    .and_then(|chain| parse_network(&chain.network))
                    .ok_or(WalletProviderError::ChainNotConfigured)?;
                authenticate(
                    &BitcoinVerifier::new(network),
                    &challenge.raw_message,
                    &signature,
                    &opts,
                )
                .await
                .map(|_| "bitcoin")
                .map_err(verification_error)
            }
            _ => return Err(WalletProviderError::UnsupportedNamespace),
        }?;
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

    fn validate_account(&self, account: &CaipAccount) -> Result<&'static str, WalletProviderError> {
        match account.namespace.as_str() {
            "eip155" if self.config.chains.eip155.contains_key(&account.reference) => {
                siwx_evm::validate_address(&account.address).map_err(verification_error)?;
                Ok("hex")
            }
            "solana" if self.config.chains.solana.contains(&account.reference) => {
                siwx_svm::validate_address(&account.address).map_err(verification_error)?;
                Ok("base58")
            }
            "bip122" if self.config.chains.bip122.contains_key(&account.reference) => {
                BitcoinVerifier::validate_address(&account.address).map_err(verification_error)?;
                Ok("bip322")
            }
            "eip155" | "solana" | "bip122" => Err(WalletProviderError::ChainNotConfigured),
            _ => Err(WalletProviderError::UnsupportedNamespace),
        }
    }

    fn verification_methods(&self, account: &CaipAccount) -> Vec<&'static str> {
        match account.namespace.as_str() {
            "eip155"
                if self
                    .config
                    .chains
                    .eip155
                    .get(&account.reference)
                    .is_some_and(|chain| chain.rpc.is_some()) =>
            {
                vec!["eoa", "erc1271", "erc6492"]
            }
            "eip155" => vec!["eoa"],
            "solana" => vec!["solana"],
            "bip122" => vec!["bip322"],
            _ => Vec::new(),
        }
    }
}

fn decode_signature(namespace: &str, signature: &str) -> Result<Vec<u8>, WalletProviderError> {
    if signature.len() > 262_144 {
        return Err(WalletProviderError::SignatureTooLarge);
    }
    match namespace {
        "eip155" => hex::decode(signature.strip_prefix("0x").unwrap_or(signature))
            .map_err(|_| WalletProviderError::InvalidSignatureEncoding),
        "solana" => bs58::decode(signature)
            .into_vec()
            .map_err(|_| WalletProviderError::InvalidSignatureEncoding),
        "bip122" => Ok(signature.as_bytes().to_vec()),
        _ => Err(WalletProviderError::UnsupportedNamespace),
    }
}

fn protocol_error(error: siwx::SiwxError) -> WalletProviderError {
    tracing::warn!(%error, "SIWX wallet challenge rejected");
    drop(error);
    WalletProviderError::InvalidAccount
}

fn verification_error(error: siwx::SiwxError) -> WalletProviderError {
    let backend = matches!(&error, siwx::SiwxError::Backend { .. });
    tracing::warn!(%error, "SIWX wallet proof rejected");
    drop(error);
    if backend {
        WalletProviderError::Backend
    } else {
        WalletProviderError::Verification
    }
}

fn evm_error(error: EvmVerificationError) -> WalletProviderError {
    match error {
        EvmVerificationError::ContractVerificationNotConfigured => {
            WalletProviderError::ContractVerificationNotConfigured
        }
        EvmVerificationError::MethodMismatch => WalletProviderError::VerificationMethodMismatch,
        EvmVerificationError::Verification(error) => verification_error(error),
    }
}
