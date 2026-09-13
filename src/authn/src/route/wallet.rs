//! CAIP/SIWX wallet authentication routes.

use axum::routing::post;
use axum::Router;

use crate::wallet::{challenge, link, verify, WalletHandler};

pub(crate) fn router(handler: WalletHandler) -> Router {
    Router::new()
        .route("/auth/wallet/challenge", post(challenge))
        .route("/auth/wallet/verify", post(verify))
        .route("/auth/wallet/link", post(link))
        .with_state(handler)
}
