use std::collections::BTreeMap;

use authguard_common::config::{EvmWalletChainProperties, OidcProviderProperties};
use serde_json::json;

use super::*;

#[test]
fn discovery_exposes_capabilities_without_provider_secrets() {
    let mut config = AuthnProperties::default();
    let oidc = OidcProviderProperties {
        issuer: "https://id.example".to_string(),
        client_secret: "must-not-leak".to_string(),
        ..OidcProviderProperties::default()
    };
    config.providers.insert("corporate".to_string(), ProviderProperties::Oidc(oidc));
    config.standalone.enabled = true;
    config.standalone.webauthn.enabled = true;
    config.wallet.enabled = true;
    config.wallet.chains.eip155 = BTreeMap::from([(
        "1".to_string(),
        EvmWalletChainProperties { rpc: Some("https://secret-rpc.example".to_string()) },
    )]);

    let value =
        serde_json::to_value(MetaRoutes::build_metadata(&config, None)).expect("metadata JSON");
    assert_eq!(value["oauth2"]["providers"][0]["id"], "corporate");
    assert_eq!(value["standalone"]["webauthn"], true);
    assert_eq!(value["wallet"]["chains"], json!(["eip155:1"]));
    assert_eq!(value["wallet"]["contractVerificationChains"], json!(["eip155:1"]));
    let rendered = value.to_string();
    assert!(!rendered.contains("must-not-leak"));
    assert!(!rendered.contains("secret-rpc"));
}
