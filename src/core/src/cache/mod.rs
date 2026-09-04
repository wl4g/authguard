mod memory;
mod redis;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;

use crate::config::CacheConfig;
pub use memory::MemoryAuthorizationCache;
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
pub async fn open(config: &CacheConfig) -> anyhow::Result<Arc<dyn IAuthorizationCache>> {
    match config.provider.to_ascii_lowercase().as_str() {
        "memory" => Ok(Arc::new(MemoryAuthorizationCache::new(&config.memory))),
        "redis" | "redis_cluster" => Ok(Arc::new(
            RedisAuthorizationCache::connect(&config.redis)
                .await
                .context("open Redis Cluster authorization cache")?,
        )),
        provider => anyhow::bail!("unsupported authorization cache provider `{provider}`"),
    }
}
