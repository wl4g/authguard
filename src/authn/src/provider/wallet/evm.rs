use siwx::{authenticate, AuthOpts};
use siwx_evm::EvmVerifier;

use super::WalletVerificationMethod;

pub(super) struct EvmVerification<'a> {
    pub contract_verifier: Option<&'a EvmVerifier>,
}

pub(super) enum EvmVerificationError {
    ContractVerificationNotConfigured,
    MethodMismatch,
    Verification(siwx::SiwxError),
}

impl EvmVerification<'_> {
    pub async fn verify(
        &self,
        raw_message: &str,
        signature: &[u8],
        opts: &AuthOpts,
        requested_method: WalletVerificationMethod,
    ) -> Result<&'static str, EvmVerificationError> {
        if has_erc6492_suffix(signature) {
            if !matches!(
                requested_method,
                WalletVerificationMethod::Auto | WalletVerificationMethod::Erc6492
            ) {
                return Err(EvmVerificationError::MethodMismatch);
            }
            return self.verify_contract(raw_message, signature, opts, "erc6492").await;
        }
        if requested_method == WalletVerificationMethod::Erc6492 {
            return Err(EvmVerificationError::MethodMismatch);
        }
        let eoa_error = match authenticate(&EvmVerifier::new(), raw_message, signature, opts).await
        {
            Ok(_) if requested_method != WalletVerificationMethod::Erc1271 => return Ok("eoa"),
            Ok(_) => return Err(EvmVerificationError::MethodMismatch),
            Err(error) => error,
        };
        if requested_method == WalletVerificationMethod::Eoa {
            return Err(EvmVerificationError::Verification(eoa_error));
        }
        let Some(contract_verifier) = self.contract_verifier else {
            return if requested_method == WalletVerificationMethod::Erc1271 {
                Err(EvmVerificationError::ContractVerificationNotConfigured)
            } else {
                Err(EvmVerificationError::Verification(eoa_error))
            };
        };
        authenticate(contract_verifier, raw_message, signature, opts)
            .await
            .map_err(EvmVerificationError::Verification)?;
        Ok("erc1271")
    }

    async fn verify_contract(
        &self,
        raw_message: &str,
        signature: &[u8],
        opts: &AuthOpts,
        method: &'static str,
    ) -> Result<&'static str, EvmVerificationError> {
        let verifier = self
            .contract_verifier
            .ok_or(EvmVerificationError::ContractVerificationNotConfigured)?;
        authenticate(verifier, raw_message, signature, opts)
            .await
            .map_err(EvmVerificationError::Verification)?;
        Ok(method)
    }
}

fn has_erc6492_suffix(signature: &[u8]) -> bool {
    const MAGIC: [u8; 32] = [
        0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64,
        0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
        0x64, 0x92,
    ];
    signature.ends_with(&MAGIC)
}
