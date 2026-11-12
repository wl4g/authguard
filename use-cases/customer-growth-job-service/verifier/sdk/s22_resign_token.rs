use super::*;

#[test]
fn bearer_prefix_is_stripped() {
    assert_eq!(
        ResignTokenVerifier::bearer_prefix_stripped(&HeaderValue::from_static("Bearer token")),
        Some("token")
    );
    assert_eq!(
        ResignTokenVerifier::bearer_prefix_stripped(&HeaderValue::from_static("Bearer")),
        None
    );
    assert_eq!(
        ResignTokenVerifier::bearer_prefix_stripped(&HeaderValue::from_static("Basic abc")),
        None
    );
}

#[test]
fn compact_token_requires_exactly_three_parts() {
    assert!(ResignTokenVerifier::compact_parts("a.b.c").is_ok());
    assert!(ResignTokenVerifier::compact_parts("a.b").is_err());
    assert!(ResignTokenVerifier::compact_parts("a.b.c.d").is_err());
    assert!(ResignTokenVerifier::compact_parts(".b.c").is_err());
    assert!(ResignTokenVerifier::compact_parts("a.b.").is_err());
}
