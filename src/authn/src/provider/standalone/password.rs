use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

const DUMMY_PASSWORD: &str = "authguard-constant-time-placeholder";

#[derive(Clone)]
pub(crate) struct PasswordVerifier {
    minimum_length: usize,
    dummy_hash: String,
}

impl PasswordVerifier {
    pub(crate) fn new(minimum_length: usize) -> anyhow::Result<Self> {
        Ok(Self { minimum_length, dummy_hash: hash_sync(DUMMY_PASSWORD)? })
    }

    pub(crate) fn validate_new(&self, password: &str) -> bool {
        password.len() >= self.minimum_length && password.len() <= 1024
    }

    pub(crate) async fn hash(&self, password: String) -> anyhow::Result<String> {
        tokio::task::spawn_blocking(move || hash_sync(&password)).await?
    }

    pub(crate) async fn verify(&self, password: String, encoded_hash: Option<String>) -> bool {
        let hash = encoded_hash.unwrap_or_else(|| self.dummy_hash.clone());
        tokio::task::spawn_blocking(move || verify_sync(&password, &hash)).await.unwrap_or(false)
    }
}

fn argon2id() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default())
}

fn hash_sync(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    argon2id()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn verify_sync(password: &str, encoded_hash: &str) -> bool {
    PasswordHash::new(encoded_hash)
        .ok()
        .is_some_and(|hash| argon2id().verify_password(password.as_bytes(), &hash).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn password_hash_is_argon2id_phc_and_verifies() {
        let verifier = PasswordVerifier::new(12).expect("password verifier");
        let hash = verifier.hash("correct horse battery staple".to_string()).await.expect("hash");
        assert!(hash.starts_with("$argon2id$v=19$"));
        assert!(
            verifier.verify("correct horse battery staple".to_string(), Some(hash.clone())).await
        );
        assert!(!verifier.verify("wrong".to_string(), Some(hash)).await);
    }
}
