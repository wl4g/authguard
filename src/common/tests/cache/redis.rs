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
