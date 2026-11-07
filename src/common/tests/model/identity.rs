use axum::http::{header, HeaderMap, HeaderValue};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use super::*;

#[test]
fn extracts_only_canonical_identity_and_safe_scalar_claims() {
    let payload = URL_SAFE_NO_PAD.encode(
            br#"{"principal_id":"P123","principal_kind":"USER","authguard_group_ids":["G2","G1","G1"],"provider":"github","sub":"987","tenant":"acme","amr":["pwd","mfa"]}"#,
        );
    let context = AuthenticatedPrincipalContext::from_verified_jwt(&format!("x.{payload}.x"))
        .expect("canonical context");
    assert_eq!(context.principal_id, "P123");
    assert_eq!(context.stable_group_ids, ["G1", "G2"]);
    assert!(!context.trusted_claims.contains_key("provider"));
    assert_eq!(context.trusted_claims.get("tenant").map(String::as_str), Some("acme"));
    assert_eq!(context.trusted_claims.get("mfa").map(String::as_str), Some("true"));
}

#[test]
fn accepts_the_gateway_validated_browser_cookie_transport() {
    let payload = URL_SAFE_NO_PAD
        .encode(br#"{"principal_id":"P123","principal_kind":"USER","authguard_group_ids":[]}"#);
    let token = format!("x.{payload}.x");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("theme=dark; authguard_token={token}")).expect("cookie"),
    );
    let context = AuthenticatedPrincipalContext::from_gateway_headers(
        &headers,
        "authorization",
        "principal_id",
        "principal_kind",
        "authguard_group_ids",
    )
    .expect("cookie identity");
    assert_eq!(context.principal_id, "P123");
}
