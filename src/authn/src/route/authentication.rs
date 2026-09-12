//! OAuth/OAuth-like browser flow routes.

use axum::routing::get;
use axum::Router;

use crate::handler::authentication::{authorize, callback, AuthenticationHandler};

pub(crate) fn router(handler: AuthenticationHandler) -> Router {
    Router::new()
        .route("/auth/v1/providers/{provider}/authorize", get(authorize))
        .route("/auth/v1/providers/{provider}/callback", get(callback))
        .with_state(handler)
}
