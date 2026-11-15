//! LDAP password login routes, independent of standalone credentials.

use crate::handler::LdapHandler;
use axum::{routing::post, Router};

pub(crate) struct LdapRoutes;

impl LdapRoutes {
    pub(crate) fn router(handler: LdapHandler) -> Router {
        Router::new().route("/auth/ldap/login", post(LdapHandler::login)).with_state(handler)
    }
}
