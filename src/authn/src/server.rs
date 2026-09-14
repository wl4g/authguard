//! `AuthN` process bootstrap and listener lifecycle.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use authguard_common::apm::propagate_http_trace_context;
use authguard_common::apm::{init_telemetry, AuthnMetrics, TelemetryConfig};
use authguard_common::cache::ICache;
use authguard_common::config::AppConfig;
use authguard_common::route::management::{self, ManagementState, ReadinessProbe};
use axum::middleware;

#[cfg(feature = "web3")]
use crate::handler::WalletHandler;
use crate::handler::{AuthnRuntime, OAuth2Handler, StandaloneHandler};

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

/// Starts the authentication service and waits for shutdown.
///
/// # Errors
///
/// Returns an error for invalid configuration, telemetry, storage, or listener startup.
pub async fn run() -> anyhow::Result<()> {
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
    let oauth = OAuth2Handler::open(metrics.clone(), &runtime).await?;
    let standalone = StandaloneHandler::open(&runtime)?;
    #[cfg(feature = "web3")]
    let wallet = WalletHandler::open(&runtime)?;
    let management = management::router(
        config.get_mgmt(),
        ManagementState::new(
            Arc::new(metrics),
            Arc::new(AuthnReadiness { challenges: runtime.challenges.clone() }),
        ),
    );
    let mut app = crate::route::meta::router();
    if let Some(handler) = oauth {
        app = app.merge(crate::route::authentication::router(handler));
    }
    if let Some(handler) = standalone {
        app = app.merge(crate::route::standalone::router(handler));
    }
    #[cfg(feature = "web3")]
    if let Some(handler) = wallet {
        app = app.merge(crate::route::wallet::router(handler));
    }
    let app = app.merge(management).layer(middleware::from_fn(propagate_http_trace_context));
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
