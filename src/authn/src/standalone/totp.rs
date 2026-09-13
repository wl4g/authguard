use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use rand::RngCore as _;
use totp_rs::{Algorithm, Builder, Secret, Totp};

use authguard_common::config::TotpAuthnProperties;

#[derive(Clone)]
pub(super) struct TotpService {
    config: TotpAuthnProperties,
    cipher: Aes256Gcm,
}

impl TotpService {
    pub(super) fn new(config: TotpAuthnProperties, encryption_key: &str) -> anyhow::Result<Self> {
        let key =
            STANDARD.decode(encryption_key).or_else(|_| URL_SAFE_NO_PAD.decode(encryption_key))?;
        if key.len() != 32 {
            anyhow::bail!("authn.standalone.credentialEncryptionKey must encode 32 bytes");
        }
        Ok(Self {
            config,
            cipher: Aes256Gcm::new_from_slice(&key)
                .map_err(|_| anyhow::anyhow!("invalid credential encryption key"))?,
        })
    }

    pub(super) fn generate(&self, account_name: &str) -> anyhow::Result<(String, String)> {
        let secret = Secret::generate();
        let base32 = secret.to_base32();
        let totp = self.build(secret, account_name)?;
        Ok((base32, totp.to_url()?))
    }

    pub(super) fn check(
        &self,
        secret_base32: &str,
        account_name: &str,
        code: &str,
    ) -> anyhow::Result<Option<u64>> {
        let secret = Secret::try_from_base32(secret_base32)?;
        Ok(self.build(secret, account_name)?.check_current(code))
    }

    pub(super) fn encrypt(&self, plaintext: &str, credential_id: &str) -> anyhow::Result<String> {
        let mut nonce = [0_u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload { msg: plaintext.as_bytes(), aad: credential_id.as_bytes() },
            )
            .map_err(|_| anyhow::anyhow!("encrypt credential secret"))?;
        let mut encoded = nonce.to_vec();
        encoded.extend_from_slice(&ciphertext);
        Ok(format!("v1:{}", URL_SAFE_NO_PAD.encode(encoded)))
    }

    pub(super) fn decrypt(&self, encoded: &str, credential_id: &str) -> anyhow::Result<String> {
        let payload = encoded
            .strip_prefix("v1:")
            .ok_or_else(|| anyhow::anyhow!("unsupported credential encryption version"))?;
        let bytes = URL_SAFE_NO_PAD.decode(payload)?;
        if bytes.len() <= 12 {
            anyhow::bail!("invalid encrypted credential secret");
        }
        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&bytes[..12]),
                Payload { msg: &bytes[12..], aad: credential_id.as_bytes() },
            )
            .map_err(|_| anyhow::anyhow!("decrypt credential secret"))?;
        String::from_utf8(plaintext).map_err(Into::into)
    }

    fn build(&self, secret: Secret, account_name: &str) -> anyhow::Result<Totp> {
        Ok(Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_digits(self.config.digits)
            .with_skew(self.config.skew)
            .with_step_duration(self.config.step_seconds)
            .with_secret(secret)
            .with_issuer(Some(self.config.issuer.as_str()))
            .with_account_name(account_name)
            .build()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_secret_is_bound_to_credential() {
        let service =
            TotpService::new(TotpAuthnProperties::default(), &STANDARD.encode([7_u8; 32]))
                .expect("TOTP service");
        let encrypted = service.encrypt("JBSWY3DPEHPK3PXP", "cred-1").expect("encrypt");
        assert_ne!(encrypted, "JBSWY3DPEHPK3PXP");
        assert_eq!(service.decrypt(&encrypted, "cred-1").expect("decrypt"), "JBSWY3DPEHPK3PXP");
        assert!(service.decrypt(&encrypted, "cred-2").is_err());
    }
}
