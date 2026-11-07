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
#[path = "../../tests/authentication/challenge.rs"]
mod tests;
