//! `AuthN` process bootstrap and listener lifecycle.

use anyhow::Context as _;
use authguard_common::apm::{init_telemetry, AuthnMetrics, TelemetryConfig};
use authguard_common::config::AppConfig;
use std::net::SocketAddr;

use crate::handler::AuthnRuntime;
use crate::route::AuthnRoutes;

/// Starts the authentication service and waits for shutdown.
///
/// # Errors
///
/// Returns an error for invalid configuration, telemetry, storage, or listener startup.
pub async fn run(bind: SocketAddr) -> anyhow::Result<()> {
    let config = AppConfig::get();
    let telemetry = init_telemetry(&TelemetryConfig::from_settings(
        "authguard-authn",
        config.get_logging(),
        &config.get_mgmt().otel,
    ))
    .context("configure AuthN telemetry")?;
    let metrics = AuthnMetrics::default();
    #[cfg(not(feature = "web3"))]
    if config.get_authn().wallet.enabled {
        anyhow::bail!("authn.wallet.enabled=true requires the AuthN `web3` build feature");
    }
    let runtime = AuthnRuntime::open().await?;
    let app = AuthnRoutes::build(metrics, &runtime).await?;
    let listener = tokio::net::TcpListener::bind(bind).await.context("bind AuthN listener")?;
    tracing::info!(%bind, "AuthGuard AuthN listener started");
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .context("serve AuthN");
    telemetry.shutdown();
    result
}
