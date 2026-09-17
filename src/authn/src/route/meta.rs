//! Public, secret-free authentication capability discovery.

use authguard_common::config::{AppConfig, AuthnProperties, ProviderProperties};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::handler::AuthenticationPipeline;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticationMetadata {
    version: &'static str,
    oauth2: OAuth2Metadata,
    standalone: StandaloneMetadata,
    wallet: WalletMetadata,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OAuth2Metadata {
    providers: Vec<OAuth2ProviderMetadata>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OAuth2ProviderMetadata {
    id: String,
    protocol: &'static str,
    issuer: String,
    authorization_endpoint: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // Independent public capability flags are intentional.
struct StandaloneMetadata {
    enabled: bool,
    password: bool,
    totp: bool,
    webauthn: bool,
    login_endpoint: &'static str,
    registration_endpoint: &'static str,
    webauthn_registration_challenge_endpoint: &'static str,
    webauthn_registration_verify_endpoint: &'static str,
    webauthn_authentication_challenge_endpoint: &'static str,
    webauthn_authentication_verify_endpoint: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletMetadata {
    enabled: bool,
    chains: Vec<String>,
    contract_verification_chains: Vec<String>,
    challenge_endpoint: &'static str,
    verify_endpoint: &'static str,
    link_endpoint: &'static str,
}

pub(crate) fn router(pipeline: std::sync::Arc<AuthenticationPipeline>) -> Router {
    Router::new()
        .route("/.well-known/authn.json", get(metadata))
        .route("/.well-known/jwks.json", get(jwks))
        .with_state(pipeline)
}

async fn metadata() -> Json<AuthenticationMetadata> {
    Json(build_metadata(AppConfig::get().get_authn()))
}

async fn jwks(
    State(pipeline): State<std::sync::Arc<AuthenticationPipeline>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    pipeline.jwks().map(Json).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

fn build_metadata(config: &AuthnProperties) -> AuthenticationMetadata {
    let providers = config
        .providers
        .iter()
        .map(|(id, provider)| {
            let (protocol, issuer) = match provider {
                ProviderProperties::Oidc(properties) => ("oidc", &properties.issuer),
                ProviderProperties::OAuth2(properties) => ("oauth2", &properties.issuer),
                ProviderProperties::OAuth2Like(properties) => ("oauth2-like", &properties.issuer),
                ProviderProperties::Custom(properties) => ("custom", &properties.issuer),
            };
            OAuth2ProviderMetadata {
                id: id.clone(),
                protocol,
                issuer: issuer.clone(),
                authorization_endpoint: format!("/auth/oauth2/{id}/authorize"),
            }
        })
        .collect();
    let mut chains = config
        .wallet
        .chains
        .eip155
        .keys()
        .map(|reference| format!("eip155:{reference}"))
        .chain(config.wallet.chains.solana.iter().map(|reference| format!("solana:{reference}")))
        .chain(config.wallet.chains.bip122.keys().map(|reference| format!("bip122:{reference}")))
        .collect::<Vec<_>>();
    chains.sort();
    let contract_verification_chains = config
        .wallet
        .chains
        .eip155
        .iter()
        .filter(|(_, chain)| chain.rpc.is_some())
        .map(|(reference, _)| format!("eip155:{reference}"))
        .collect();
    AuthenticationMetadata {
        version: "1",
        oauth2: OAuth2Metadata { providers },
        standalone: StandaloneMetadata {
            enabled: config.standalone.enabled,
            password: config.standalone.enabled,
            totp: config.standalone.enabled && config.standalone.totp.enabled,
            webauthn: config.standalone.enabled && config.standalone.webauthn.enabled,
            login_endpoint: "/auth/standalone/login",
            registration_endpoint: "/auth/standalone/register",
            webauthn_registration_challenge_endpoint:
                "/auth/standalone/webauthn/register/challenge",
            webauthn_registration_verify_endpoint: "/auth/standalone/webauthn/register/verify",
            webauthn_authentication_challenge_endpoint:
                "/auth/standalone/webauthn/authenticate/challenge",
            webauthn_authentication_verify_endpoint:
                "/auth/standalone/webauthn/authenticate/verify",
        },
        wallet: WalletMetadata {
            enabled: config.wallet.enabled && cfg!(feature = "web3"),
            chains,
            contract_verification_chains,
            challenge_endpoint: "/auth/wallet/challenge",
            verify_endpoint: "/auth/wallet/verify",
            link_endpoint: "/auth/wallet/link",
        },
    }
}

#[cfg(test)]
mod tests {
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

        let value = serde_json::to_value(build_metadata(&config)).expect("metadata JSON");
        assert_eq!(value["oauth2"]["providers"][0]["id"], "corporate");
        assert_eq!(value["standalone"]["webauthn"], true);
        assert_eq!(value["wallet"]["chains"], json!(["eip155:1"]));
        assert_eq!(value["wallet"]["contractVerificationChains"], json!(["eip155:1"]));
        let rendered = value.to_string();
        assert!(!rendered.contains("must-not-leak"));
        assert!(!rendered.contains("secret-rpc"));
    }
}
