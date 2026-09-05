#![allow(clippy::unused_async)] // Axum handlers must return futures.

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::get;
use axum::Router;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::compression::CompressionLayer;
use tower_http::timeout::TimeoutLayer;

use super::admin::AdminRoutes;
use super::middleware::{HttpMetrics, TraceContext};
use crate::apm::MetricsRegistry;
use crate::config::AuthguardConfig;
use crate::handler::{ManagementHandler, PolicyHandler, PrincipalHandler};

#[derive(Clone)]
struct ManagementRouteState {
    handler: ManagementHandler,
    metrics: MetricsRegistry,
}

pub struct ManagementRoutes {
    state: ManagementRouteState,
    policy: PolicyHandler,
    principals: PrincipalHandler,
    config: AuthguardConfig,
}

impl ManagementRoutes {
    #[must_use]
    pub fn new(
        policy: PolicyHandler,
        principals: PrincipalHandler,
        management: ManagementHandler,
        metrics: MetricsRegistry,
        config: AuthguardConfig,
    ) -> Self {
        Self {
            state: ManagementRouteState { handler: management, metrics },
            policy,
            principals,
            config,
        }
    }

    pub fn router(self) -> Router {
        let mut operational = Router::new()
            .route(&self.config.mgmt.health.liveness_path, get(Self::liveness))
            .route(&self.config.mgmt.health.readiness_path, get(Self::readiness));
        if self.config.mgmt.metrics.enabled {
            operational = operational.route(&self.config.mgmt.metrics.path, get(Self::metrics));
        }
        let endpoints = operational.with_state(self.state.clone()).merge(
            AdminRoutes::new(
                self.policy,
                self.principals,
                self.state.metrics.clone(),
                Some(self.config.auth.admin_token.clone()),
            )
            .router(),
        );
        let service = if self.config.mgmt.context_path == "/" {
            endpoints
        } else {
            Router::new().nest(&self.config.mgmt.context_path, endpoints)
        };
        service
            .layer(DefaultBodyLimit::max(self.config.server.request.max_message_bytes))
            .layer(ConcurrencyLimitLayer::new(
                self.config.server.performance.max_in_flight_requests,
            ))
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                self.config.server.request.timeout,
            ))
            .layer(CatchPanicLayer::new())
            .layer(CompressionLayer::new())
            .layer(middleware::from_fn(TraceContext::propagate))
            .layer(middleware::from_fn_with_state(
                HttpMetrics::new(self.state.metrics),
                HttpMetrics::observe,
            ))
    }

    async fn liveness() -> &'static str {
        "ok"
    }

    async fn readiness(State(state): State<ManagementRouteState>) -> (StatusCode, &'static str) {
        match state.handler.readiness().await {
            Ok(()) => (StatusCode::OK, "ready"),
            Err(error) => {
                tracing::warn!(%error, "authorization dependency readiness check failed");
                (StatusCode::SERVICE_UNAVAILABLE, "not ready")
            }
        }
    }

    async fn metrics(
        State(state): State<ManagementRouteState>,
    ) -> ([(axum::http::HeaderName, &'static str); 1], String) {
        let body = state.handler.metrics().unwrap_or_else(|error| {
            tracing::error!(error = %error, "failed to render Prometheus metrics");
            String::new()
        });
        (
            [(
                axum::http::header::CONTENT_TYPE,
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
            )],
            body,
        )
    }
}
