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
    let app = AuthnRoutes::build(metrics.clone(), &runtime).await?;
    if config.mgmt.enabled && bind == config.mgmt_addr() {
        anyhow::bail!("AuthN API and mgmt must use different listener addresses");
    }
    let listener = tokio::net::TcpListener::bind(bind).await.context("bind AuthN API listener")?;
    tracing::info!(%bind, "AuthGuard AuthN API listener started");
    let result = if config.mgmt.enabled {
        let management_address = config.mgmt_addr();
        let management_listener = tokio::net::TcpListener::bind(management_address)
            .await
            .with_context(|| format!("bind AuthN management listener {management_address}"))?;
        let management = AuthnRoutes::management(metrics, &runtime);
        tracing::info!(server.address = %management_address, "AuthGuard AuthN management endpoints listening");
        tokio::try_join!(
            async {
                axum::serve(listener, app)
                    .with_graceful_shutdown(shutdown_signal())
                    .await
                    .context("serve AuthN API")
            },
            async {
                axum::serve(management_listener, management)
                    .with_graceful_shutdown(shutdown_signal())
                    .await
                    .context("serve AuthN management endpoints")
            }
        )
        .map(|_| ())
    } else {
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .context("serve AuthN API")
    };
    telemetry.shutdown();
    result
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
