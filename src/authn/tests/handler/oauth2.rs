use std::collections::BTreeMap;

use serde_json::json;

use super::*;

#[test]
fn distinguishes_legacy_json_completion_from_hosted_login_redirect() {
    assert_eq!(
        AuthorizeQuery { return_uri: "/legacy-client".to_string(), return_to: String::new() }
            .return_destination()
            .expect("legacy completion"),
        ("/legacy-client".to_string(), false)
    );
    assert_eq!(
        AuthorizeQuery { return_uri: String::new(), return_to: "/hosted-login".to_string() }
            .return_destination()
            .expect("hosted completion"),
        ("/hosted-login".to_string(), true)
    );
    assert!(AuthorizeQuery { return_uri: "/one".to_string(), return_to: "/two".to_string() }
        .return_destination()
        .is_err());
}

#[test]
fn oidc_authentication_preserves_the_actual_evidence() {
    let authentication = provider_authentication(
        ExternalIdentity {
            provider: "corporate".to_string(),
            issuer: "https://id.example".to_string(),
            subject: "123".to_string(),
            claims: BTreeMap::from([
                ("amr".to_string(), json!(["pwd", "otp"])),
                ("acr".to_string(), json!("urn:example:mfa")),
            ]),
        },
        ProviderProtocol::Oidc,
    );
    assert_eq!(authentication.amr, ["pwd", "otp"]);
    assert_eq!(authentication.acr.as_deref(), Some("urn:example:mfa"));
    assert!(!authentication.external_identity.claims.contains_key("amr"));
    assert!(!authentication.external_identity.claims.contains_key("acr"));
}
