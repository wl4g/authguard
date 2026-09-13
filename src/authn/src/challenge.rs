//! Redis-backed one-time state for every interactive authentication ceremony.

use std::time::Duration;

use async_trait::async_trait;
use authguard_common::config::RedisClusterProperties;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore as _;
use redis::cluster::ClusterClientBuilder;
use redis::cluster_async::ClusterConnection;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error)]
pub enum ChallengeStoreError {
    #[error("challenge state backend failed")]
    Backend,
    #[error("challenge state is invalid")]
    InvalidState,
}

#[async_trait]
pub trait ChallengeStore: Send + Sync {
    async fn put(
        &self,
        purpose: &str,
        challenge_id: &str,
        payload: &[u8],
        ttl: Duration,
    ) -> Result<bool, ChallengeStoreError>;

    async fn consume(
        &self,
        purpose: &str,
        challenge_id: &str,
    ) -> Result<Option<Vec<u8>>, ChallengeStoreError>;

    async fn ping(&self) -> Result<(), ChallengeStoreError>;
}

#[derive(Clone)]
pub struct RedisChallengeStore {
    connection: ClusterConnection,
    key_prefix: String,
}

impl RedisChallengeStore {
    /// Opens and verifies the Redis cluster connection used for one-time state.
    ///
    /// # Errors
    ///
    /// Returns an error when configuration, connection, or the initial health
    /// check fails.
    pub async fn connect(config: &RedisClusterProperties) -> anyhow::Result<Self> {
        let mut builder = ClusterClientBuilder::new(config.nodes.clone())
            .connection_timeout(config.connection_timeout)
            .response_timeout(config.response_timeout)
            .retries(config.retries)
            .max_retry_wait(duration_millis(config.max_retry_wait))
            .min_retry_wait(duration_millis(config.min_retry_wait));
        if !config.username.is_empty() {
            builder = builder.username(&config.username);
        }
        if !config.password.is_empty() {
            builder = builder.password(&config.password);
        }
        let client = builder.build()?;
        let mut connection = client.get_async_connection().await?;
        redis::cmd("PING").query_async::<String>(&mut connection).await?;
        Ok(Self { connection, key_prefix: config.key_prefix.trim_end_matches(':').to_string() })
    }

    fn key(&self, purpose: &str, challenge_id: &str) -> String {
        challenge_key(&self.key_prefix, purpose, challenge_id)
    }
}

#[async_trait]
impl ChallengeStore for RedisChallengeStore {
    async fn put(
        &self,
        purpose: &str,
        challenge_id: &str,
        payload: &[u8],
        ttl: Duration,
    ) -> Result<bool, ChallengeStoreError> {
        let mut connection = self.connection.clone();
        let response = redis::cmd("SET")
            .arg(self.key(purpose, challenge_id))
            .arg(payload)
            .arg("NX")
            .arg("EX")
            .arg(ttl.as_secs().max(1))
            .query_async::<Option<String>>(&mut connection)
            .await
            .map_err(|error| {
                tracing::error!(%error, "store authentication challenge in Redis failed");
                ChallengeStoreError::Backend
            })?;
        Ok(response.is_some())
    }

    async fn consume(
        &self,
        purpose: &str,
        challenge_id: &str,
    ) -> Result<Option<Vec<u8>>, ChallengeStoreError> {
        let mut connection = self.connection.clone();
        redis::cmd("GETDEL")
            .arg(self.key(purpose, challenge_id))
            .query_async(&mut connection)
            .await
            .map_err(|error| {
                tracing::error!(%error, "consume authentication challenge from Redis failed");
                ChallengeStoreError::Backend
            })
    }

    async fn ping(&self) -> Result<(), ChallengeStoreError> {
        let mut connection = self.connection.clone();
        redis::cmd("PING")
            .query_async::<String>(&mut connection)
            .await
            .map(|_| ())
            .map_err(|_| ChallengeStoreError::Backend)
    }
}

#[must_use]
pub fn random_challenge_id() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Serializes and stores a one-time challenge payload.
///
/// # Errors
///
/// Returns an error for serialization, collision, or Redis failure.
pub async fn put_json<T: Serialize>(
    store: &dyn ChallengeStore,
    purpose: &str,
    challenge_id: &str,
    payload: &T,
    ttl: Duration,
) -> Result<(), ChallengeStoreError> {
    let payload = serde_json::to_vec(payload).map_err(|_| ChallengeStoreError::InvalidState)?;
    if store.put(purpose, challenge_id, &payload, ttl).await? {
        Ok(())
    } else {
        Err(ChallengeStoreError::Backend)
    }
}

/// Atomically consumes and deserializes a one-time challenge payload.
///
/// # Errors
///
/// Returns an error for deserialization or Redis failure.
pub async fn consume_json<T: DeserializeOwned>(
    store: &dyn ChallengeStore,
    purpose: &str,
    challenge_id: &str,
) -> Result<Option<T>, ChallengeStoreError> {
    store
        .consume(purpose, challenge_id)
        .await?
        .map(|payload| {
            serde_json::from_slice(&payload).map_err(|_| ChallengeStoreError::InvalidState)
        })
        .transpose()
}

fn challenge_key(key_prefix: &str, purpose: &str, challenge_id: &str) -> String {
    let digest = Sha256::digest(format!("{purpose}\0{challenge_id}").as_bytes());
    format!("{key_prefix}:authn-challenge:v1:{digest:x}")
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct MemoryStore(Mutex<HashMap<String, Vec<u8>>>);

    #[async_trait]
    impl ChallengeStore for MemoryStore {
        async fn put(
            &self,
            purpose: &str,
            challenge_id: &str,
            payload: &[u8],
            _ttl: Duration,
        ) -> Result<bool, ChallengeStoreError> {
            let key = challenge_key("test", purpose, challenge_id);
            let mut entries = self.0.lock().expect("challenge store");
            if entries.contains_key(&key) {
                return Ok(false);
            }
            entries.insert(key, payload.to_vec());
            Ok(true)
        }

        async fn consume(
            &self,
            purpose: &str,
            challenge_id: &str,
        ) -> Result<Option<Vec<u8>>, ChallengeStoreError> {
            Ok(self.0.lock().expect("challenge store").remove(&challenge_key(
                "test",
                purpose,
                challenge_id,
            )))
        }

        async fn ping(&self) -> Result<(), ChallengeStoreError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn consume_is_one_time() {
        let store = MemoryStore::default();
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
    fn redis_keys_do_not_expose_purpose_or_nonce() {
        let key = challenge_key("authguard", "wallet", "secret-nonce");
        assert!(key.starts_with("authguard:authn-challenge:v1:"));
        assert!(!key.contains("wallet"));
        assert!(!key.contains("secret-nonce"));
    }
}
