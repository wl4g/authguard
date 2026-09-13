//! OAuth/OAuth-like browser flow routes.

use axum::routing::{get, post};
use axum::Router;

use crate::handler::authentication::{
    authorize, callback, link_authorize, token_exchange, AuthenticationHandler,
};

pub(crate) fn router(handler: AuthenticationHandler) -> Router {
    Router::new()
        .route("/auth/oauth2/{provider}/authorize", get(authorize))
        .route("/auth/oauth2/{provider}/link", post(link_authorize))
        .route("/auth/oauth2/{provider}/callback", get(callback))
        .route("/auth/oauth2/{provider}/token-exchange", post(token_exchange))
        .with_state(handler)
}
