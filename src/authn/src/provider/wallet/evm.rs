use siwx::{authenticate, AuthOpts};
use siwx_evm::EvmVerifier;

pub(super) struct EvmVerification<'a> {
    pub verifier: &'a EvmVerifier,
}

impl EvmVerification<'_> {
    pub async fn verify(
        &self,
        raw_message: &str,
        signature: &[u8],
        opts: &AuthOpts,
    ) -> Result<&'static str, siwx::SiwxError> {
        if authenticate(&EvmVerifier::new(), raw_message, signature, opts).await.is_ok() {
            return Ok("eoa");
        }
        authenticate(self.verifier, raw_message, signature, opts).await?;
        if has_erc6492_suffix(signature) {
            Ok("erc6492")
        } else {
            Ok("erc1271")
        }
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
