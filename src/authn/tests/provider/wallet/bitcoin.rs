use super::*;

#[test]
fn verifies_bip322_simple_and_rejects_message_substitution() {
    let address = "bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3";
    let signature = "smpAUHd69PrJQEv+oKTfZ8l+WROBHuy9HKrbFCJu7U1iK2iiEy1vMU5EfMtjc+VSHM7aU0SDbak5IUZRVno2P5mjSafAQ==";
    assert!(verify_bip322(address, "Hello World", signature).is_ok());
    assert!(verify_bip322(address, "different", signature).is_err());
}
