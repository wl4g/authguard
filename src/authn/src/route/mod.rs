//! `AuthN` HTTP route composition.
//!
//! Process bootstrap delegates route wiring here so protocol handlers remain
//! cohesive and the server lifecycle does not acquire provider knowledge.

use std::sync::Arc;

use async_trait::async_trait;
use authguard_common::apm::propagate_http_trace_context;
use authguard_common::apm::AuthnMetrics;
use authguard_common::cache::ICache;
use authguard_common::config::AppConfig;
use authguard_common::route::management::{self, ManagementState, ReadinessProbe};
use axum::middleware;
use axum::Router;

#[cfg(feature = "web3")]
use crate::handler::WalletHandler;
use crate::handler::{AuthnRuntime, OAuth2Handler, StandaloneHandler};

pub(crate) mod application;
mod authentication;
mod meta;
mod standalone;
#[cfg(feature = "web3")]
mod wallet;
mod webauthn;

pub(crate) struct AuthnRoutes;

struct AuthnReadiness {
    challenges: Option<Arc<dyn ICache>>,
}

#[async_trait]
impl ReadinessProbe for AuthnReadiness {
    async fn ready(&self) -> anyhow::Result<()> {
        if let Some(challenges) = &self.challenges {
            challenges.ping().await?;
        }
        Ok(())
    }
}

impl AuthnRoutes {
    pub(crate) async fn build(
        metrics: AuthnMetrics,
        runtime: &AuthnRuntime,
    ) -> anyhow::Result<Router> {
        let oauth = OAuth2Handler::open(metrics.clone(), runtime).await?;
        let standalone = StandaloneHandler::open(runtime)?;
        #[cfg(feature = "web3")]
        let wallet = WalletHandler::open(runtime)?;

        let mut routes = meta::MetaRoutes::router(runtime.pipeline.clone());
        if let Some(handler) = oauth {
            routes = routes.merge(authentication::OAuth2Routes::router(handler));
        }
        if let Some(handler) = standalone {
            routes = routes
                .merge(standalone::StandaloneRoutes::router(handler.clone()))
                .merge(webauthn::WebauthnRoutes::router(handler));
        }
        #[cfg(feature = "web3")]
        if let Some(handler) = wallet {
            routes = routes.merge(wallet::WalletRoutes::router(handler));
        }
        Ok(routes.layer(middleware::from_fn(propagate_http_trace_context)))
    }

    pub(crate) fn management(metrics: AuthnMetrics, runtime: &AuthnRuntime) -> Router {
        management::router(
            AppConfig::get().get_mgmt(),
            ManagementState::new(
                Arc::new(metrics),
                Arc::new(AuthnReadiness { challenges: runtime.challenges.clone() }),
            ),
        )
        .layer(middleware::from_fn(propagate_http_trace_context))
    }
}
