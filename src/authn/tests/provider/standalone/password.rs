use super::*;

#[tokio::test]
async fn password_hash_is_argon2id_phc_and_verifies() {
    let verifier = PasswordVerifier::new(12).expect("password verifier");
    let hash = verifier.hash("correct horse battery staple".to_string()).await.expect("hash");
    assert!(hash.starts_with("$argon2id$v=19$"));
    assert!(verifier.verify("correct horse battery staple".to_string(), Some(hash.clone())).await);
    assert!(!verifier.verify("wrong".to_string(), Some(hash)).await);
}
