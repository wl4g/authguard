//! OAuth/OAuth-like browser flow routes.

use axum::routing::{get, post};
use axum::Router;

use crate::handler::authentication::{authorize, callback, token_exchange, AuthenticationHandler};

pub(crate) fn router(handler: AuthenticationHandler) -> Router {
    Router::new()
        .route("/auth/v1/providers/{provider}/authorize", get(authorize))
        .route("/auth/v1/providers/{provider}/callback", get(callback))
        .route("/auth/v1/providers/{provider}/token-exchange", post(token_exchange))
        .with_state(handler)
}
