use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;

use super::IAuthorizationCache;
use crate::config::MemoryCacheConfig;
use crate::model::epoch_seconds;

pub struct MemoryAuthorizationCache {
    scopes: Mutex<MemoryScopes>,
    max_capacity: usize,
    default_ttl: Duration,
}

struct MemoryScopes {
    entries: HashMap<String, MemoryScope>,
    next_access_sequence: u64,
}

struct MemoryScope {
    encoded_context: String,
    expires_at_epoch_seconds: u64,
    last_access_sequence: u64,
}

impl MemoryAuthorizationCache {
    #[must_use]
    pub fn new(config: &MemoryCacheConfig) -> Self {
        Self {
            scopes: Mutex::new(MemoryScopes {
                entries: HashMap::with_capacity(config.initial_capacity.min(config.max_capacity)),
                next_access_sequence: 0,
            }),
            max_capacity: config.max_capacity,
            default_ttl: config.ttl,
        }
    }

    fn expires_at(&self, ttl: Duration) -> u64 {
        let effective_ttl = ttl.min(self.default_ttl).as_secs().max(1);
        epoch_seconds().saturating_add(effective_ttl)
    }
}

impl Default for MemoryAuthorizationCache {
    fn default() -> Self {
        Self::new(&MemoryCacheConfig::default())
    }
}

#[async_trait]
impl IAuthorizationCache for MemoryAuthorizationCache {
    async fn store_scope(
        &self,
        token: &str,
        encoded_context: &str,
        ttl: Duration,
    ) -> anyhow::Result<()> {
        let mut scopes = self.scopes.lock().await;
        let now = epoch_seconds();
        scopes.entries.retain(|_, scope| scope.expires_at_epoch_seconds > now);
        if !scopes.entries.contains_key(token) && scopes.entries.len() >= self.max_capacity {
            let least_recently_used = scopes
                .entries
                .iter()
                .min_by_key(|(_, scope)| scope.last_access_sequence)
                .map(|(token, _)| token.clone());
            if let Some(token) = least_recently_used {
                scopes.entries.remove(&token);
            }
        }
        scopes.next_access_sequence = scopes.next_access_sequence.saturating_add(1);
        let last_access_sequence = scopes.next_access_sequence;
        scopes.entries.insert(
            token.to_string(),
            MemoryScope {
                encoded_context: encoded_context.to_string(),
                expires_at_epoch_seconds: self.expires_at(ttl),
                last_access_sequence,
            },
        );
        Ok(())
    }

    async fn load_scope(&self, token: &str) -> anyhow::Result<Option<String>> {
        let mut scopes = self.scopes.lock().await;
        let now = epoch_seconds();
        scopes.entries.retain(|_, scope| scope.expires_at_epoch_seconds > now);
        scopes.next_access_sequence = scopes.next_access_sequence.saturating_add(1);
        let next_access_sequence = scopes.next_access_sequence;
        Ok(scopes.entries.get_mut(token).map(|scope| {
            scope.last_access_sequence = next_access_sequence;
            scope.encoded_context.clone()
        }))
    }

    async fn ping(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn evicts_the_least_recently_used_scope() {
        let cache = MemoryAuthorizationCache::new(&MemoryCacheConfig {
            initial_capacity: 1,
            max_capacity: 2,
            ttl: Duration::from_secs(60),
            eviction_policy: "LRU".to_string(),
        });
        cache.store_scope("token-a", "context-a", Duration::from_secs(30)).await.unwrap();
        cache.store_scope("token-b", "context-b", Duration::from_secs(30)).await.unwrap();
        assert_eq!(cache.load_scope("token-a").await.unwrap().as_deref(), Some("context-a"));

        cache.store_scope("token-c", "context-c", Duration::from_secs(30)).await.unwrap();

        assert_eq!(cache.load_scope("token-b").await.unwrap(), None);
        assert_eq!(cache.load_scope("token-a").await.unwrap().as_deref(), Some("context-a"));
        assert_eq!(cache.load_scope("token-c").await.unwrap().as_deref(), Some("context-c"));
    }

    #[tokio::test]
    async fn removes_expired_scope_entries() {
        let cache = MemoryAuthorizationCache::default();
        cache.store_scope("token", "context", Duration::from_secs(30)).await.unwrap();
        cache.scopes.lock().await.entries.get_mut("token").unwrap().expires_at_epoch_seconds = 0;
        assert!(cache.load_scope("token").await.unwrap().is_none());
    }
}
