
use super::*;

#[test]
fn access_context_round_trips_as_base64url_json() {
    let now = epoch_seconds();
    let expected = AccessContext::new(
        AccessContextInput {
            principal_id: "principal-user-1".to_string(),
            action: "job.read".to_string(),
            resource_urn: "urn:iam:prod:customer-growth:global:example-corp:job/1".to_string(),
            allow_resource_urns: vec![
                "urn:iam:prod:customer-growth:global:example-corp:job/*".to_string()
            ],
            deny_resource_urns: Vec::new(),
            policy_revision: 7,
        },
        now,
        std::time::Duration::from_secs(30),
    );
    let encoded = expected.encode().expect("encode");
    assert!(!encoded.contains('='));
    assert_eq!(AccessContext::decode(&encoded).expect("decode"), expected);
}

#[test]
fn expired_context_is_rejected() {
    let context = AccessContext::new(
        AccessContextInput {
            principal_id: "principal-user-1".to_string(),
            action: "job.read".to_string(),
            resource_urn: "urn:iam:prod:customer-growth:global:example-corp:job/1".to_string(),
            allow_resource_urns: Vec::new(),
            deny_resource_urns: Vec::new(),
            policy_revision: 7,
        },
        100,
        std::time::Duration::from_secs(1),
    );
    assert!(matches!(context.validate(101), Err(AccessContextError::Expired)));
}

#[test]
fn direct_context_signature_detects_tampering() {
    let codec = AccessContextSigner::new([7_u8; 32]).expect("signer");
    let compact = codec.sign_encoded("payload").expect("sign");
    assert_eq!(codec.verify(&compact).expect("verify"), "payload");
    assert!(matches!(
        codec.verify(&compact.replace("payload", "tampered")),
        Err(AccessContextError::InvalidSignature)
    ));
}
