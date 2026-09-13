use std::future::ready;
use std::str::FromStr as _;

use bitcoin::address::NetworkUnchecked;
use bitcoin::sign_message::{signed_msg_hash, MessageSignature};
use bitcoin::{Address, Network};
use siwx::{ChainIdReason, SiwxError, SiwxMessage, Verifier};

#[derive(Clone, Copy)]
pub(super) struct BitcoinVerifier {
    network: Network,
}

impl BitcoinVerifier {
    pub(super) fn new(network: Network) -> Self {
        Self { network }
    }
}

impl Verifier for BitcoinVerifier {
    const CHAIN_NAME: &'static str = "Bitcoin";
    const NAMESPACE: &'static str = "bip122";

    fn validate_address(address: &str) -> Result<(), SiwxError> {
        Address::<NetworkUnchecked>::from_str(address)
            .map(|_| ())
            .map_err(|error| SiwxError::InvalidAddress { reason: error.to_string() })
    }

    fn validate_chain_id(chain_id: &str) -> Result<(), SiwxError> {
        if chain_id.is_empty()
            || chain_id.len() > 64
            || !chain_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(SiwxError::InvalidChainId { reason: ChainIdReason::BadCharset });
        }
        Ok(())
    }

    fn verify(
        &self,
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
    ) -> impl std::future::Future<Output = Result<(), SiwxError>> + Send {
        let result = (|| {
            let address = Address::<NetworkUnchecked>::from_str(message.address())
                .map_err(|error| SiwxError::InvalidAddress { reason: error.to_string() })?
                .require_network(self.network)
                .map_err(|error| SiwxError::InvalidAddress { reason: error.to_string() })?;
            let signature = MessageSignature::from_slice(signature)
                .map_err(|error| SiwxError::InvalidSignature { reason: error.to_string() })?;
            let verified = signature
                .is_signed_by_address(
                    &bitcoin::secp256k1::Secp256k1::verification_only(),
                    &address,
                    signed_msg_hash(raw_message),
                )
                .map_err(|error| SiwxError::InvalidSignature { reason: error.to_string() })?;
            if verified {
                Ok(())
            } else {
                Err(SiwxError::VerificationFailed {
                    reason: "Bitcoin message signature does not match account".to_string(),
                })
            }
        })();
        ready(result)
    }
}

pub(super) fn parse_network(value: &str) -> Option<Network> {
    match value {
        "bitcoin" | "bitcoin-mainnet" => Some(Network::Bitcoin),
        "testnet" | "bitcoin-testnet" => Some(Network::Testnet),
        "signet" | "bitcoin-signet" => Some(Network::Signet),
        "regtest" | "bitcoin-regtest" => Some(Network::Regtest),
        _ => None,
    }
}
