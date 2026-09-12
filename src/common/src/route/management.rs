//! Common health, metrics, and runtime-diagnostics routes.

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use crate::apm::metrics::MetricsRenderer;
use crate::apm::pprof;
use crate::config::ManagementProperties;

#[async_trait]
pub trait ReadinessProbe: Send + Sync {
    async fn ready(&self) -> anyhow::Result<()>;
}

#[derive(Clone)]
pub struct ManagementState {
    metrics: Arc<dyn MetricsRenderer>,
    readiness: Arc<dyn ReadinessProbe>,
}

impl ManagementState {
    #[must_use]
    pub fn new(metrics: Arc<dyn MetricsRenderer>, readiness: Arc<dyn ReadinessProbe>) -> Self {
        Self { metrics, readiness }
    }
}

pub fn router(config: &ManagementProperties, state: ManagementState) -> Router {
    let routes = endpoints(config, state);
    if config.context_path == "/" {
        routes
    } else {
        Router::new().nest(&config.context_path, routes)
    }
}

pub fn endpoints(config: &ManagementProperties, state: ManagementState) -> Router {
    let mut routes = Router::new()
        .route(&config.health.liveness_path, get(liveness))
        .route(&config.health.readiness_path, get(readiness))
        .route("/_/pprof", get(runtime_profile));
    if config.metrics.enabled {
        routes = routes.route("/_/metrics", get(metrics));
        if config.metrics.path != "/_/metrics" {
            routes = routes.route(&config.metrics.path, get(metrics));
        }
    }
    routes.with_state(state)
}

async fn liveness() -> &'static str {
    "ok"
}

async fn readiness(State(state): State<ManagementState>) -> Response {
    match state.readiness.ready().await {
        Ok(()) => (StatusCode::OK, "ready").into_response(),
        Err(error) => {
            tracing::warn!(%error, "service dependency readiness check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "not ready").into_response()
        }
    }
}

async fn metrics(State(state): State<ManagementState>) -> Response {
    match state.metrics.render_metrics() {
        Ok(body) => (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static(
                    "application/openmetrics-text; version=1.0.0; charset=utf-8",
                ),
            )],
            body,
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to render Prometheus metrics");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn runtime_profile() -> Json<pprof::RuntimeProfile> {
    Json(pprof::snapshot())
}
