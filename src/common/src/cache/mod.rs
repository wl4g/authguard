mod memory;
#[cfg(feature = "redis-cache")]
mod redis;

use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "redis-cache")]
use anyhow::Context as _;
use async_trait::async_trait;

use crate::config::AppConfig;
pub use memory::MemoryAuthorizationCache;
#[cfg(feature = "redis-cache")]
pub use redis::RedisAuthorizationCache;

#[async_trait]
pub trait IAuthorizationCache: Send + Sync {
    async fn store_scope(
        &self,
        token: &str,
        encoded_context: &str,
        ttl: Duration,
    ) -> anyhow::Result<()>;
    async fn load_scope(&self, token: &str) -> anyhow::Result<Option<String>>;
    async fn ping(&self) -> anyhow::Result<()>;
}

/// Opens the configured authorization cache implementation.
///
/// # Errors
///
/// Returns an error when the provider is unsupported or cannot be initialized.
pub async fn open() -> anyhow::Result<Arc<dyn IAuthorizationCache>> {
    let app_config = AppConfig::get();
    let config = app_config.get_cache();
    match config.provider.to_ascii_lowercase().as_str() {
        "memory" => Ok(Arc::new(MemoryAuthorizationCache::new(&config.memory))),
        "redis" | "redis_cluster" => {
            #[cfg(feature = "redis-cache")]
            {
                Ok(Arc::new(
                    RedisAuthorizationCache::connect(&config.redis)
                        .await
                        .context("open Redis Cluster authorization cache")?,
                ))
            }
            #[cfg(not(feature = "redis-cache"))]
            {
                anyhow::bail!("Redis cache support is not enabled in this service build")
            }
        }
        provider => anyhow::bail!("unsupported authorization cache provider `{provider}`"),
    }
}
