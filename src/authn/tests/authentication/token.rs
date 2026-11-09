use std::collections::{BTreeMap, HashMap};

use authguard_common::model::{ExternalIdentity, PrincipalKind};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{TimeZone as _, Utc};

use super::*;

const TEST_PRIVATE_KEY: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../use-cases/customer-growth-job-service/e2e/config/authguard/e2e-jwt-keys/resign-jwt-key.pem"
    ));

#[test]
fn every_protocol_uses_the_same_canonical_jwt_claims() {
    let mut config = AuthnProperties::default();
    config.standalone.enabled = true;
    config.token.private_key = TEST_PRIVATE_KEY.to_string();
    let issuer = TokenIssuer::from_config(&config).expect("token issuer");
    let principal = AuthenticatedPrincipalContext {
        principal_id: "P_canonical".to_string(),
        kind: PrincipalKind::User,
        stable_group_ids: vec!["G_team".to_string()],
        trusted_claims: HashMap::new(),
        acr: None,
        amr: Vec::new(),
    };
    let authenticated_at = Utc.timestamp_opt(1_700_000_000, 0).single().expect("timestamp");
    let authentication = AuthenticationResult::new(
        ExternalIdentity {
            provider: "wallet".to_string(),
            issuer: "caip-122".to_string(),
            subject: "eip155:1:0x0000000000000000000000000000000000000001".to_string(),
            claims: BTreeMap::new(),
        },
        ["wallet", "siwx", "eoa"],
        Some("urn:authguard:acr:wallet-possession".to_string()),
        authenticated_at,
    );

    let token = issuer.issue(&principal, &authentication).expect("canonical JWT");
    let payload = token.split('.').nth(1).expect("payload");
    let claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url payload"))
            .expect("JSON claims");

    assert_eq!(claims["sub"], "P_canonical");
    assert_eq!(claims["principal_id"], "P_canonical");
    assert_eq!(claims["amr"], json!(["wallet", "siwx", "eoa"]));
    assert_eq!(claims["acr"], "urn:authguard:acr:wallet-possession");
    assert_eq!(claims["auth_time"], 1_700_000_000_u64);
    assert!(claims["iat"].as_u64().is_some());
    assert!(claims["exp"].as_u64() > claims["iat"].as_u64());
    assert!(claims.get("provider").is_none());
    assert!(claims.get("subject").is_none());

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().expect("authorization header"),
    );
    assert_eq!(issuer.authenticate_bearer(&headers).expect("valid token"), "P_canonical");
}

#[test]
fn canonical_issuer_accepts_a_base64_pkcs8_key() {
    let mut config = AuthnProperties::default();
    config.standalone.enabled = true;
    config.token.private_key_b64 = STANDARD.encode(TEST_PRIVATE_KEY);
    TokenIssuer::from_config(&config).expect("base64 canonical token key");
}
