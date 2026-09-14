use std::future::ready;
use std::str::FromStr as _;

use bip322::Verification;
use bitcoin::address::NetworkUnchecked;
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
            Address::<NetworkUnchecked>::from_str(message.address())
                .map_err(|error| SiwxError::InvalidAddress { reason: error.to_string() })?
                .require_network(self.network)
                .map_err(|error| SiwxError::InvalidAddress { reason: error.to_string() })?;
            let signature =
                std::str::from_utf8(signature).map_err(|_| SiwxError::InvalidSignature {
                    reason: "BIP-322 signature must be UTF-8 encoded".to_string(),
                })?;
            verify_bip322(message.address(), raw_message, signature)
        })();
        ready(result)
    }
}

fn verify_bip322(address: &str, message: &str, signature: &str) -> Result<(), SiwxError> {
    let verified = match signature.get(..3) {
        Some("smp") => conclusive(bip322::verify_simple_encoded(address, message, signature))?,
        Some("ful") => conclusive(bip322::verify_full_encoded(address, message, signature))?,
        Some("pof") => conclusive(bip322::verify_pof_encoded(address, message, signature))?,
        // BIP-322 permits prefix-less simple proofs for compatibility. Legacy
        // BIP-137 is accepted only as the library's P2PKH-restricted fallback.
        _ => {
            if let Ok(result) = bip322::verify_simple_encoded(address, message, signature) {
                conclusive(Ok(result))?
            } else {
                bip322::verify_legacy_encoded(address, message, signature)
                    .map_err(|error| SiwxError::InvalidSignature { reason: error.to_string() })?;
                true
            }
        }
    };
    if verified {
        Ok(())
    } else {
        Err(SiwxError::VerificationFailed {
            reason: "BIP-322 verifier returned an inconclusive result".to_string(),
        })
    }
}

fn conclusive(result: Result<Verification, bip322::Error>) -> Result<bool, SiwxError> {
    result
        .map(|result| matches!(result, Verification::Valid { .. }))
        .map_err(|error| SiwxError::InvalidSignature { reason: error.to_string() })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_bip322_simple_and_rejects_message_substitution() {
        let address = "bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3";
        let signature = "smpAUHd69PrJQEv+oKTfZ8l+WROBHuy9HKrbFCJu7U1iK2iiEy1vMU5EfMtjc+VSHM7aU0SDbak5IUZRVno2P5mjSafAQ==";
        assert!(verify_bip322(address, "Hello World", signature).is_ok());
        assert!(verify_bip322(address, "different", signature).is_err());
    }
}
