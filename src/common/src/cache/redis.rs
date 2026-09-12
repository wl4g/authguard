use std::time::Duration;

use async_trait::async_trait;
use redis::cluster::ClusterClientBuilder;
use redis::cluster_async::ClusterConnection;
use redis::AsyncCommands as _;
use sha2::{Digest as _, Sha256};
use tokio::time::sleep;

use super::IAuthorizationCache;
use crate::config::RedisClusterProperties;

#[derive(Clone)]
pub struct RedisAuthorizationCache {
    connection: ClusterConnection,
    key_prefix: String,
}

impl RedisAuthorizationCache {
    /// Connects to Redis Cluster and verifies the initial topology.
    ///
    /// # Errors
    ///
    /// Returns an error when nodes, credentials, or topology are unavailable.
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
        for attempt in 0..=config.retries {
            let connection = async {
                let mut connection = client.get_async_connection().await?;
                redis::cmd("PING").query_async::<String>(&mut connection).await?;
                redis::RedisResult::Ok(connection)
            }
            .await;
            match connection {
                Ok(connection) => {
                    return Ok(Self {
                        connection,
                        key_prefix: config.key_prefix.trim_end_matches(':').to_string(),
                    });
                }
                Err(error) if attempt < config.retries => {
                    let delay = retry_delay(config.min_retry_wait, config.max_retry_wait, attempt);
                    tracing::warn!(
                        %error,
                        attempt = attempt + 1,
                        max_attempts = config.retries + 1,
                        retry_delay_ms = delay.as_millis(),
                        "Redis Cluster is not ready; retrying initial connection"
                    );
                    sleep(delay).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
        unreachable!("the inclusive Redis connection-attempt loop always executes")
    }

    fn scope_key(&self, token: &str) -> String {
        scope_key(&self.key_prefix, token)
    }
}

fn scope_key(key_prefix: &str, token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    // Do not use a constant Redis Cluster hash tag here. Scope tokens are
    // independent single-key records, so hashing the complete key distributes
    // them across all cluster slots instead of concentrating traffic on one
    // primary.
    format!("{key_prefix}:scope:v3:{digest:x}")
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn retry_delay(minimum: Duration, maximum: Duration, attempt: u32) -> Duration {
    minimum.saturating_mul(1_u32.checked_shl(attempt.min(31)).unwrap_or(u32::MAX)).min(maximum)
}

#[async_trait]
impl IAuthorizationCache for RedisAuthorizationCache {
    async fn store_scope(
        &self,
        token: &str,
        encoded_context: &str,
        ttl: Duration,
    ) -> anyhow::Result<()> {
        let mut connection = self.connection.clone();
        connection
            .set_ex::<_, _, ()>(self.scope_key(token), encoded_context, ttl.as_secs())
            .await?;
        Ok(())
    }

    async fn load_scope(&self, token: &str) -> anyhow::Result<Option<String>> {
        let mut connection = self.connection.clone();
        Ok(connection.get(self.scope_key(token)).await?)
    }

    async fn ping(&self) -> anyhow::Result<()> {
        let mut connection = self.connection.clone();
        redis::cmd("PING").query_async::<String>(&mut connection).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{retry_delay, scope_key};
    use std::time::Duration;

    #[test]
    fn initial_connection_backoff_grows_and_stops_at_the_configured_maximum() {
        let minimum = Duration::from_millis(100);
        let maximum = Duration::from_millis(450);

        assert_eq!(retry_delay(minimum, maximum, 0), Duration::from_millis(100));
        assert_eq!(retry_delay(minimum, maximum, 1), Duration::from_millis(200));
        assert_eq!(retry_delay(minimum, maximum, 2), Duration::from_millis(400));
        assert_eq!(retry_delay(minimum, maximum, 3), maximum);
        assert_eq!(retry_delay(minimum, maximum, u32::MAX), maximum);
    }

    #[test]
    fn scope_tokens_use_independent_cluster_keys_without_a_constant_hash_tag() {
        let first = scope_key("authguard", "token-one");
        let second = scope_key("authguard", "token-two");

        assert_ne!(first, second);
        assert!(first.starts_with("authguard:scope:v3:"));
        assert!(!first.contains('{') && !first.contains('}'));
        assert!(!second.contains('{') && !second.contains('}'));
    }
}
