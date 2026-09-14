//! Protocol-neutral one-time state for every interactive authentication ceremony.

use std::time::Duration;

use authguard_common::cache::ICache;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error)]
pub enum ChallengeError {
    #[error("challenge state backend failed")]
    Backend,
    #[error("challenge state is invalid")]
    InvalidState,
}

/// Serializes and stores a one-time challenge payload.
///
/// # Errors
///
/// Returns an error for serialization, collision, or cache-backend failure.
pub async fn put_json<T: Serialize>(
    cache: &dyn ICache,
    purpose: &str,
    challenge_id: &str,
    payload: &T,
    ttl: Duration,
) -> Result<(), ChallengeError> {
    let payload = serde_json::to_vec(payload).map_err(|_| ChallengeError::InvalidState)?;
    if cache.put_if_absent(&challenge_key(purpose, challenge_id), &payload, ttl).await.map_err(
        |error| {
            tracing::error!(%error, "store authentication challenge in cache failed");
            ChallengeError::Backend
        },
    )? {
        Ok(())
    } else {
        Err(ChallengeError::Backend)
    }
}

/// Atomically consumes and deserializes a one-time challenge payload.
///
/// # Errors
///
/// Returns an error for deserialization or cache-backend failure.
pub async fn consume_json<T: DeserializeOwned>(
    cache: &dyn ICache,
    purpose: &str,
    challenge_id: &str,
) -> Result<Option<T>, ChallengeError> {
    cache
        .take(&challenge_key(purpose, challenge_id))
        .await
        .map_err(|error| {
            tracing::error!(%error, "consume authentication challenge from cache failed");
            ChallengeError::Backend
        })?
        .map(|payload| serde_json::from_slice(&payload).map_err(|_| ChallengeError::InvalidState))
        .transpose()
}

fn challenge_key(purpose: &str, challenge_id: &str) -> String {
    let digest = Sha256::digest(format!("{purpose}\0{challenge_id}").as_bytes());
    format!("authn-challenge:v1:{digest:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use authguard_common::cache::MemoryAuthorizationCache;

    #[tokio::test]
    async fn consume_is_one_time() {
        let store = MemoryAuthorizationCache::default();
        put_json(
            &store,
            "wallet",
            "id",
            &serde_json::json!({"nonce": "n"}),
            Duration::from_secs(5),
        )
        .await
        .expect("store");
        assert!(consume_json::<serde_json::Value>(&store, "wallet", "id")
            .await
            .expect("first consume")
            .is_some());
        assert!(consume_json::<serde_json::Value>(&store, "wallet", "id")
            .await
            .expect("second consume")
            .is_none());
    }

    #[test]
    fn cache_keys_do_not_expose_purpose_or_nonce() {
        let key = challenge_key("wallet", "secret-nonce");
        assert!(key.starts_with("authn-challenge:v1:"));
        assert!(!key.contains("wallet"));
        assert!(!key.contains("secret-nonce"));
    }
}
