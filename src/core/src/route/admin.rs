use axum::middleware;
use axum::Router;

use super::middleware::AdminAuthenticator;
use super::policy::PolicyRoutes;
use super::principal::PrincipalRoutes;
use crate::apm::MetricsRegistry;
use crate::handler::{PolicyHandler, PrincipalHandler};

/// Composes authenticated control-plane resource routes.
pub struct AdminRoutes {
    policy: PolicyHandler,
    principals: PrincipalHandler,
    metrics: MetricsRegistry,
    authenticator: AdminAuthenticator,
}

impl AdminRoutes {
    #[must_use]
    pub fn new(
        policy: PolicyHandler,
        principals: PrincipalHandler,
        metrics: MetricsRegistry,
        admin_token: Option<String>,
    ) -> Self {
        Self { policy, principals, metrics, authenticator: AdminAuthenticator::new(admin_token) }
    }

    pub fn router(self) -> Router {
        PolicyRoutes::new(self.policy, self.principals.clone(), self.metrics)
            .router()
            .merge(PrincipalRoutes::new(self.principals).router())
            .route_layer(middleware::from_fn_with_state(
                self.authenticator,
                AdminAuthenticator::authenticate,
            ))
    }
}
