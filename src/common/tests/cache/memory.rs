use super::*;

#[tokio::test]
async fn evicts_the_least_recently_used_scope() {
    let cache = MemoryAuthorizationCache::new(&MemoryCacheProperties {
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
