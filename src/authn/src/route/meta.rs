//! Public, secret-free authentication capability discovery.

use authguard_common::config::{
    AppConfig, ApplicationThemeProperties, AuthnProperties, ProviderProperties,
};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::handler::ApiError;
use crate::handler::AuthenticationPipeline;
use crate::route::application::ApplicationResolver;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticationMetadata {
    version: &'static str,
    application: Option<ApplicationMetadata>,
    methods: AuthenticationMethodsMetadata,
    oauth2: OAuth2Metadata,
    standalone: StandaloneMetadata,
    wallet: WalletMetadata,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationMetadata {
    id: String,
    display_name: String,
    logo: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    theme: Option<ApplicationThemeProperties>,
}

#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)] // Public capability flags are intentionally independent.
struct AuthenticationMethodsMetadata {
    password: bool,
    totp: bool,
    webauthn: bool,
    wallet: bool,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionMetadata {
    principal: authguard_common::model::AuthenticatedPrincipalContext,
}

pub(crate) struct MetaRoutes;

impl MetaRoutes {
    pub(crate) fn router(pipeline: std::sync::Arc<AuthenticationPipeline>) -> Router {
        Router::new()
            .route("/.well-known/authn.json", get(Self::metadata))
            .route("/.well-known/jwks.json", get(Self::jwks))
            .route("/auth/session", get(Self::session))
            .route("/auth/logout", axum::routing::post(Self::logout))
            .with_state(pipeline)
    }

    // Axum handlers return futures even when their current work is synchronous.
    #[allow(clippy::unused_async)]
    async fn metadata(headers: HeaderMap) -> Result<Json<AuthenticationMetadata>, ApiError> {
        let application_config = AppConfig::get();
        let config = application_config.get_authn();
        let application =
            ApplicationResolver::new(config, &headers).resolve()?.map(|application| {
                ApplicationMetadata {
                    id: application.id,
                    display_name: application.display_name,
                    logo: application.logo,
                    theme: application.theme,
                }
            });
        Ok(Json(Self::build_metadata(config, application)))
    }

    #[allow(clippy::unused_async)]
    async fn jwks(
        State(pipeline): State<std::sync::Arc<AuthenticationPipeline>>,
    ) -> Result<Json<serde_json::Value>, StatusCode> {
        pipeline.jwks().map(Json).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
    }

    #[allow(clippy::unused_async)]
    async fn session(
        State(pipeline): State<std::sync::Arc<AuthenticationPipeline>>,
        headers: HeaderMap,
    ) -> Result<impl IntoResponse, ApiError> {
        let principal = pipeline.authenticate_browser_cookie(&headers).map_err(ApiError::token)?;
        let mut response = Json(SessionMetadata { principal }).into_response();
        response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        Ok(response)
    }

    #[allow(clippy::unused_async)]
    async fn logout() -> Response {
        let mut response = StatusCode::NO_CONTENT.into_response();
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_static(
                "authguard_token=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
            ),
        );
        response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }

    fn build_metadata(
        config: &AuthnProperties,
        application: Option<ApplicationMetadata>,
    ) -> AuthenticationMetadata {
        let providers = config
            .providers
            .iter()
            .map(|(id, provider)| {
                let (protocol, issuer) = match provider {
                    ProviderProperties::Oidc(properties) => ("oidc", &properties.issuer),
                    ProviderProperties::OAuth2(properties) => ("oauth2", &properties.issuer),
                    ProviderProperties::OAuth2Like(properties) => {
                        ("oauth2-like", &properties.issuer)
                    }
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
            .chain(
                config.wallet.chains.solana.iter().map(|reference| format!("solana:{reference}")),
            )
            .chain(
                config.wallet.chains.bip122.keys().map(|reference| format!("bip122:{reference}")),
            )
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
            application,
            methods: AuthenticationMethodsMetadata {
                password: config.standalone.enabled,
                totp: config.standalone.enabled && config.standalone.totp.enabled,
                webauthn: config.standalone.enabled && config.standalone.webauthn.enabled,
                wallet: config.wallet.enabled && cfg!(feature = "web3"),
            },
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
}
