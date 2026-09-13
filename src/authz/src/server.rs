use std::{future::Future, sync::Arc, time::Duration};

use anyhow::{anyhow, Context as _};
use axum::http::StatusCode;
use axum::{middleware, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use tonic::transport::Server;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::compression::CompressionLayer;
use tower_http::timeout::TimeoutLayer;

use crate::cache::{self, IAuthorizationCache};
use crate::config::{AppConfig, AppConfigProperties};
use crate::handler::authorization::ResignSigner;
use crate::handler::{DefaultAuthorizationHandler, PolicyHandler, PrincipalHandler};
use crate::model::AccessContextSigner;
use crate::principal::PrincipalDiscoveryComponent;
use crate::route::{ApiRoutes, EnvoyAuthzRoutes, HttpMetrics};
use crate::storage;
use authguard_common::apm::metrics::AuthzMetrics;
use authguard_common::apm::propagate_http_trace_context;
use authguard_common::apm::{init_telemetry, TelemetryConfig};
use authguard_common::route::management::{self, ManagementState, ReadinessProbe};
use authguard_common::utils::jwt as resign;

#[derive(Default)]
pub struct AuthguardServer;

struct RuntimeComponents {
    policy: PolicyHandler,
    principals: PrincipalHandler,
    authorization: DefaultAuthorizationHandler,
    cache: Arc<dyn IAuthorizationCache>,
    metrics: AuthzMetrics,
}

#[derive(Clone)]
struct AuthzReadiness {
    cache: Arc<dyn IAuthorizationCache>,
    policy: PolicyHandler,
}

struct ServerSupervisor {
    servers: tokio::task::JoinSet<anyhow::Result<()>>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    shutdown_timeout: Duration,
}

struct ServiceShutdown {
    receiver: tokio::sync::watch::Receiver<bool>,
}

struct ProcessShutdownSignal;

impl AuthguardServer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Opens runtime dependencies and serves the data and management planes.
    ///
    /// # Errors
    ///
    /// Returns an error when telemetry, storage, cache, listener binding, or serving fails.
    pub async fn run(self) -> anyhow::Result<()> {
        let config = AppConfig::get();
        let telemetry = init_telemetry(&TelemetryConfig::from_settings(
            &config.server.service_name,
            config.get_logging(),
            &config.get_mgmt().otel,
        ))
        .context("configure APM telemetry")?;
        let metrics = AuthzMetrics::default();
        tracing::info!(
            service.name = %config.server.service_name,
            authguard.storage.provider = %config.storage.provider,
            authguard.cache.provider = %config.cache.provider,
            authguard.management.enabled = config.mgmt.enabled,
            "starting Authguard runtime"
        );
        let runtime = RuntimeComponents::open(metrics).await?;
        if config.authz.api_token.is_empty() {
            tracing::warn!("control-plane APIs are disabled because authz.api_token is empty");
        }

        let mut supervisor = ServerSupervisor::new(config.server.shutdown_timeout);
        Self::spawn_authorization_plane(&mut supervisor, runtime.authorization.clone());
        Self::spawn_access_context_plane(&mut supervisor, runtime.authorization);
        Self::spawn_management_plane(
            &mut supervisor,
            runtime.policy,
            runtime.principals,
            runtime.cache,
            runtime.metrics,
        )
        .await?;

        let result = supervisor.run().await;
        match &result {
            Ok(()) => tracing::info!("Authguard runtime stopped gracefully"),
            Err(error) => tracing::error!(%error, "Authguard runtime stopped with an error"),
        }
        telemetry.shutdown();
        result
    }

    /// Constructs the management router for integration tests and embedded use.
    pub fn management_router(
        policy: PolicyHandler,
        principals: PrincipalHandler,
        cache: Arc<dyn IAuthorizationCache>,
        metrics: AuthzMetrics,
        config: &AppConfigProperties,
    ) -> Router {
        let readiness = AuthzReadiness { cache, policy: policy.clone() };
        let operational = management::endpoints(
            &config.mgmt,
            ManagementState::new(Arc::new(metrics.clone()), Arc::new(readiness)),
        );
        let endpoints = operational.merge(
            ApiRoutes::new(policy, principals, Some(config.authz.api_token.clone())).router(),
        );
        let routes = if config.mgmt.context_path == "/" {
            endpoints
        } else {
            Router::new().nest(&config.mgmt.context_path, endpoints)
        };
        routes
            .layer(axum::extract::DefaultBodyLimit::max(config.server.request.max_message_bytes))
            .layer(ConcurrencyLimitLayer::new(config.server.performance.max_in_flight_requests))
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                config.server.request.timeout,
            ))
            .layer(CatchPanicLayer::new())
            .layer(CompressionLayer::new())
            .layer(middleware::from_fn(propagate_http_trace_context))
            .layer(middleware::from_fn_with_state(HttpMetrics::new(metrics), HttpMetrics::observe))
    }

    fn spawn_authorization_plane(
        supervisor: &mut ServerSupervisor,
        authorization_handler: DefaultAuthorizationHandler,
    ) {
        let config = AppConfig::get();
        let routes = EnvoyAuthzRoutes::new(authorization_handler, config.get_server());
        let authorization = routes.authorization_service();
        let address = config.authorization_addr();
        let request_timeout = config.server.request.timeout;
        let max_in_flight = config.server.performance.max_in_flight_requests;
        let shutdown = supervisor.shutdown_signal();
        supervisor.spawn(async move {
            Server::builder()
                .timeout(request_timeout)
                .concurrency_limit_per_connection(max_in_flight)
                .add_service(authorization)
                .serve_with_shutdown(address, shutdown.wait())
                .await
                .context("serve Envoy authorization gRPC API")
        });
        tracing::info!(server.address = %address, "Authguard Envoy authorization gRPC server listening");
    }

    fn spawn_access_context_plane(
        supervisor: &mut ServerSupervisor,
        authorization_handler: DefaultAuthorizationHandler,
    ) {
        let config = AppConfig::get();
        let routes = EnvoyAuthzRoutes::new(authorization_handler, config.get_server());
        let access_context = routes.access_context_service();
        let address = config.access_context_addr();
        let request_timeout = config.server.request.timeout;
        let max_in_flight = config.server.performance.max_in_flight_requests;
        let shutdown = supervisor.shutdown_signal();
        supervisor.spawn(async move {
            Server::builder()
                .timeout(request_timeout)
                .concurrency_limit_per_connection(max_in_flight)
                .add_service(access_context)
                .serve_with_shutdown(address, shutdown.wait())
                .await
                .context("serve workload access-context gRPC API")
        });
        tracing::info!(server.address = %address, "Authguard workload access-context gRPC server listening");
    }

    async fn spawn_management_plane(
        supervisor: &mut ServerSupervisor,
        policy: PolicyHandler,
        principals: PrincipalHandler,
        cache: Arc<dyn IAuthorizationCache>,
        metrics: AuthzMetrics,
    ) -> anyhow::Result<()> {
        let config = AppConfig::get();
        if !config.mgmt.enabled {
            return Ok(());
        }
        let address = config.mgmt_addr();
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .with_context(|| format!("bind management listener {address}"))?;
        let routes = Self::management_router(policy, principals, cache, metrics, &config);
        let shutdown = supervisor.shutdown_signal();
        supervisor.spawn(async move {
            axum::serve(listener, routes)
                .with_graceful_shutdown(shutdown.wait())
                .await
                .context("serve management API")
        });
        tracing::info!(server.address = %address, "Authguard management server listening");
        Ok(())
    }
}

#[async_trait::async_trait]
impl ReadinessProbe for AuthzReadiness {
    async fn ready(&self) -> anyhow::Result<()> {
        self.cache.ping().await?;
        self.policy.readiness().await
    }
}

impl ServerSupervisor {
    fn new(shutdown_timeout: Duration) -> Self {
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
        Self { servers: tokio::task::JoinSet::new(), shutdown_tx, shutdown_timeout }
    }

    fn spawn<F>(&mut self, server: F)
    where
        F: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        self.servers.spawn(server);
    }

    fn shutdown_signal(&self) -> ServiceShutdown {
        ServiceShutdown { receiver: self.shutdown_tx.subscribe() }
    }

    async fn run(mut self) -> anyhow::Result<()> {
        let first_error = tokio::select! {
            () = ProcessShutdownSignal::wait() => {
                tracing::info!("shutdown signal received");
                None
            },
            result = self.servers.join_next() => {
                Some(match result {
                    Some(Ok(Ok(()))) => anyhow!("server exited before shutdown signal"),
                    Some(Ok(Err(error))) => error,
                    Some(Err(error)) => anyhow!("server task failed: {error}"),
                    None => anyhow!("no server task was started"),
                })
            },
        };
        tracing::info!(
            server.graceful_shutdown_timeout_ms = self.shutdown_timeout.as_millis(),
            "coordinating Authguard service shutdown"
        );
        let _ = self.shutdown_tx.send(true);
        let graceful_shutdown = async {
            let mut error = first_error;
            while let Some(result) = self.servers.join_next().await {
                let result =
                    result.unwrap_or_else(|error| Err(anyhow!("server task failed: {error}")));
                if error.is_none() {
                    error = result.err();
                }
            }
            error
        };
        let Ok(server_error) = tokio::time::timeout(self.shutdown_timeout, graceful_shutdown).await
        else {
            self.servers.abort_all();
            tracing::error!(
                server.graceful_shutdown_timeout_ms = self.shutdown_timeout.as_millis(),
                "Authguard graceful shutdown timed out; remaining tasks were aborted"
            );
            return Err(anyhow!(
                "graceful shutdown exceeded {} seconds",
                self.shutdown_timeout.as_secs_f64()
            ));
        };
        server_error.map_or(Ok(()), Err)
    }
}

impl ServiceShutdown {
    async fn wait(mut self) {
        while !self.requested().await {}
    }

    async fn requested(&mut self) -> bool {
        if *self.receiver.borrow() {
            return true;
        }
        self.receiver.changed().await.is_err() || *self.receiver.borrow()
    }
}

impl ProcessShutdownSignal {
    async fn wait() {
        let ctrl_c = async {
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(%error, "failed to install Ctrl+C handler");
            }
        };
        #[cfg(unix)]
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    let _ = signal.recv().await;
                }
                Err(error) => tracing::error!(%error, "failed to install SIGTERM handler"),
            }
        };
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            () = ctrl_c => {},
            () = terminate => {},
        }
    }
}

impl RuntimeComponents {
    /// Opens the runtime dependencies from their config sub-objects.
    ///
    /// Each component package owns its own startup: storage and cache open
    /// themselves, principal discovery is assembled by
    /// [`PrincipalDiscoveryComponent`], and the policy runtime opens against
    /// the shared repositories.
    async fn open(metrics: AuthzMetrics) -> anyhow::Result<Self> {
        let config = AppConfig::get();
        let cache = cache::open().await?;
        tracing::info!(
            authguard.cache.provider = %config.cache.provider,
            "authorization scope cache is ready"
        );
        let (policy_repository, principal_repository): (
            Arc<dyn storage::PolicyRepository>,
            Arc<dyn storage::PrincipalRepository>,
        ) = match config.storage.provider.to_ascii_lowercase().as_str() {
            "sqlite" => {
                let repository = Arc::new(
                    storage::AuthzSqliteRepository::connect(&config.storage.sqlite).await?,
                );
                (repository.clone(), repository)
            }
            "postgres" => {
                let repository = Arc::new(
                    storage::AuthzPostgresRepository::connect(&config.storage.postgres).await?,
                );
                (repository.clone(), repository)
            }
            provider => anyhow::bail!("unsupported IAM storage provider `{provider}`"),
        };
        tracing::info!(
            authguard.storage.provider = %config.storage.provider,
            "authorization storage is ready"
        );
        let principals = PrincipalDiscoveryComponent::new(principal_repository.clone())?.handler();
        let policy = PolicyHandler::open(
            policy_repository,
            principal_repository,
            metrics.clone(),
            config.storage.bootstrap_policy.clone(),
        )
        .await?;
        let authorization_catalog = policy.catalog();
        tracing::info!(
            authguard.policy.revision = authorization_catalog.revision,
            authguard.policy.action_count = authorization_catalog.actions.len(),
            authguard.policy.role_count = authorization_catalog.roles.len(),
            authguard.policy.role_binding_count = authorization_catalog.role_bindings.len(),
            "authorization policy runtime is ready"
        );
        let resign = Self::open_resign_signer(&config.authz.resign)?;
        let authorization = DefaultAuthorizationHandler::new(
            policy.clone(),
            principals.clone(),
            cache.clone(),
            metrics.clone(),
            config.authz.identity.clone(),
            config.authz.scope_delivery.clone(),
            AccessContextSigner::from_env()
                .context("configure direct access-context signing key")?,
            resign,
        );
        Ok(Self { policy, principals, authorization, cache, metrics })
    }

    /// Opens the RS256 resign-JWT signing key from its file-or-inline key.
    ///
    /// Disabled configuration yields `None` and the original identity token is
    /// simply stripped. The private key never leaves this process; business
    /// workloads only hold the paired public key.
    fn open_resign_signer(
        config: &crate::config::ResignProperties,
    ) -> anyhow::Result<Option<ResignSigner>> {
        if !config.enabled {
            return Ok(None);
        }
        let private_key_pem = STANDARD
            .decode(config.private_key_b64.trim())
            .context("decode authz.resign.private_key_b64")?;
        let private_key_pem = String::from_utf8(private_key_pem)
            .context("authz.resign.private_key_b64 is not UTF-8 PKCS#8 PEM")?;
        resign::load_signing_key(&private_key_pem)
            .context("configure resign JWT RSA signing key")
            .map(|key| Some(ResignSigner::new(key, config.max_ttl)))
    }
}
