use super::ApiAuthenticator;

#[test]
fn compares_api_tokens_without_early_byte_exit() {
    assert!(ApiAuthenticator::constant_time_eq(b"secret", b"secret"));
    assert!(!ApiAuthenticator::constant_time_eq(b"secret", b"secrex"));
    assert!(!ApiAuthenticator::constant_time_eq(b"secret", b"short"));
}
