use super::*;
use authguard_common::cache::MemoryAuthorizationCache;

#[tokio::test]
async fn consume_is_one_time() {
    let store = MemoryAuthorizationCache::default();
    put_json(&store, "wallet", "id", &serde_json::json!({"nonce": "n"}), Duration::from_secs(5))
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
