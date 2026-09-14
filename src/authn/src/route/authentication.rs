//! OAuth/OAuth-like browser flow routes.

use axum::routing::{get, post};
use axum::Router;

use crate::handler::oauth2::{authorize, callback, link_authorize, token_exchange, OAuth2Handler};

pub(crate) fn router(handler: OAuth2Handler) -> Router {
    Router::new()
        .route("/auth/oauth2/{provider}/authorize", get(authorize))
        .route("/auth/oauth2/{provider}/link", post(link_authorize))
        .route("/auth/oauth2/{provider}/callback", get(callback))
        .route("/auth/oauth2/{provider}/token-exchange", post(token_exchange))
        .with_state(handler)
}
