//! `AuthN` process bootstrap and listener lifecycle.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use authguard_common::apm::propagate_http_trace_context;
use authguard_common::apm::{init_telemetry, AuthnMetrics, TelemetryConfig};
use authguard_common::config::{AppConfig, CONFIG_FILE_ENV, DEFAULT_CONFIG};
use authguard_common::route::management::{self, ManagementState, ReadinessProbe};
use axum::middleware;

use crate::handler::AuthenticationHandler;

struct AuthnReadiness;

#[async_trait]
impl ReadinessProbe for AuthnReadiness {
    async fn ready(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Starts the authentication service and waits for shutdown.
///
/// # Errors
///
/// Returns an error for invalid configuration, telemetry, storage, or listener startup.
pub async fn run() -> anyhow::Result<()> {
    let config_file = std::env::var(CONFIG_FILE_ENV).unwrap_or_else(|_| DEFAULT_CONFIG.to_string());
    let config = AppConfig::load_authn(&config_file)?;
    let telemetry = init_telemetry(&TelemetryConfig::from_settings(
        "authguard-authn",
        config.get_logging(),
        &config.get_mgmt().otel,
    ))
    .context("configure AuthN telemetry")?;
    let metrics = AuthnMetrics::default();
    let handler = AuthenticationHandler::open(metrics.clone()).await?;
    let management = management::router(
        config.get_mgmt(),
        ManagementState::new(Arc::new(metrics), Arc::new(AuthnReadiness)),
    );
    let app = crate::route::authentication::router(handler)
        .merge(management)
        .layer(middleware::from_fn(propagate_http_trace_context));
    let bind = std::env::var("AUTHGUARD_AUTHN_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8082".to_string())
        .parse::<SocketAddr>()
        .context("parse AUTHGUARD_AUTHN_BIND")?;
    let listener = tokio::net::TcpListener::bind(bind).await.context("bind AuthN listener")?;
    tracing::info!(%bind, "AuthGuard AuthN listener started");
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve AuthN");
    telemetry.shutdown();
    result
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
