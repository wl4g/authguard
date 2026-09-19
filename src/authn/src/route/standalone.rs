//! Standalone password and TOTP routes.

use axum::routing::post;
use axum::Router;

use crate::handler::standalone::{
    login, register, totp_enrollment_challenge, totp_enrollment_verify, StandaloneHandler,
};

pub(crate) struct StandaloneRoutes;

impl StandaloneRoutes {
    pub(crate) fn router(handler: StandaloneHandler) -> Router {
        Router::new()
            .route("/auth/standalone/register", post(register))
            .route("/auth/register", post(register))
            .route("/auth/standalone/login", post(login))
            .route("/auth/login", post(login))
            .route("/auth/standalone/totp/challenge", post(totp_enrollment_challenge))
            .route("/auth/totp/challenge", post(totp_enrollment_challenge))
            .route("/auth/standalone/totp/verify", post(totp_enrollment_verify))
            .route("/auth/totp/verify", post(totp_enrollment_verify))
            .with_state(handler)
    }
}
