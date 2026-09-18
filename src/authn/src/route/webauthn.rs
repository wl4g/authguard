//! `WebAuthn` registration and authentication ceremony routes.

use axum::routing::post;
use axum::Router;

use crate::handler::standalone::{
    webauthn_authentication_challenge, webauthn_authentication_verify,
    webauthn_registration_challenge, webauthn_registration_verify, StandaloneHandler,
};

pub(crate) struct WebauthnRoutes;

impl WebauthnRoutes {
    pub(crate) fn router(handler: StandaloneHandler) -> Router {
        Router::new()
            .route(
                "/auth/standalone/webauthn/register/challenge",
                post(webauthn_registration_challenge),
            )
            .route("/auth/standalone/webauthn/register/verify", post(webauthn_registration_verify))
            .route("/auth/webauthn/register/challenge", post(webauthn_registration_challenge))
            .route("/auth/webauthn/register/verify", post(webauthn_registration_verify))
            .route(
                "/auth/standalone/webauthn/authenticate/challenge",
                post(webauthn_authentication_challenge),
            )
            .route(
                "/auth/standalone/webauthn/authenticate/verify",
                post(webauthn_authentication_verify),
            )
            .route("/auth/webauthn/authenticate/challenge", post(webauthn_authentication_challenge))
            .route("/auth/webauthn/authenticate/verify", post(webauthn_authentication_verify))
            .with_state(handler)
    }
}
