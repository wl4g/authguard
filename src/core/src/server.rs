use std::{future::Future, sync::Arc, time::Duration};

use anyhow::{anyhow, Context as _};
use axum::Router;
use tonic::transport::Server;

use crate::apm::{APMComponent, MetricsRegistry};
use crate::cache::{self, IAuthorizationCache};
use crate::config::AuthguardConfig;
use crate::handler::{
    DefaultAuthorizationHandler, ManagementHandler, PolicyHandler, PrincipalHandler,
};
use crate::model::{AccessContextSigner, BusinessTokenSigner};
use crate::principal::PrincipalDiscoveryComponent;
use crate::route::{AuthorizationRoutes, ManagementRoutes};
use crate::storage;

pub struct AuthguardServer {
    config: AuthguardConfig,
}

struct RuntimeComponents {
    policy: PolicyHandler,
    principals: PrincipalHandler,
    authorization: DefaultAuthorizationHandler,
    cache: Arc<dyn IAuthorizationCache>,
    metrics: MetricsRegistry,
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
    pub fn new(config: AuthguardConfig) -> Self {
        Self { config }
    }

    /// Opens runtime dependencies and serves the data and management planes.
    ///
    /// # Errors
    ///
    /// Returns an error when telemetry, storage, cache, listener binding, or serving fails.
    pub async fn run(self) -> anyhow::Result<()> {
        let apm =
            APMComponent::open(&self.config.server, &self.config.logging, &self.config.mgmt.otel)
                .context("configure APM telemetry")?;
        tracing::info!(
            service.name = %self.config.server.service_name,
            authguard.storage.provider = %self.config.storage.provider,
            authguard.cache.provider = %self.config.cache.provider,
            authguard.management.enabled = self.config.mgmt.enabled,
            "starting Authguard runtime"
        );
        let runtime = RuntimeComponents::open(&self.config, apm.metrics()).await?;
        if self.config.auth.admin_token.is_empty() {
            tracing::warn!("control-plane APIs are disabled because auth.admin_token is empty");
        }

        let mut supervisor = ServerSupervisor::new(self.config.server.shutdown_timeout);
        self.spawn_policy_refresh(&mut supervisor, runtime.policy.clone());
        self.spawn_authorization_plane(&mut supervisor, runtime.authorization.clone());
        self.spawn_access_context_plane(&mut supervisor, runtime.authorization);
        self.spawn_management_plane(
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
        apm.shutdown();
        result
    }

    /// Constructs the management router for integration tests and embedded use.
    pub fn management_router(
        policy: PolicyHandler,
        principals: PrincipalHandler,
        cache: Arc<dyn IAuthorizationCache>,
        metrics: MetricsRegistry,
        config: AuthguardConfig,
    ) -> Router {
        let management = ManagementHandler::new(
            cache,
            policy.clone(),
            config.storage.policy_max_staleness,
            metrics.clone(),
        );
        ManagementRoutes::new(policy, principals, management, metrics, config).router()
    }

    fn spawn_policy_refresh(&self, supervisor: &mut ServerSupervisor, policy: PolicyHandler) {
        let interval = self.config.storage.policy_refresh_interval;
        let shutdown = supervisor.shutdown_signal();
        supervisor.spawn(async move {
            PolicyRefreshTask::new(policy, interval).run(shutdown).await;
            Ok(())
        });
    }

    fn spawn_authorization_plane(
        &self,
        supervisor: &mut ServerSupervisor,
        authorization_handler: DefaultAuthorizationHandler,
    ) {
        let routes = AuthorizationRoutes::new(authorization_handler, &self.config.server);
        let authorization = routes.authorization_service();
        let address = self.config.authorization_addr();
        let request_timeout = self.config.server.request.timeout;
        let max_in_flight = self.config.server.performance.max_in_flight_requests;
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
        &self,
        supervisor: &mut ServerSupervisor,
        authorization_handler: DefaultAuthorizationHandler,
    ) {
        let routes = AuthorizationRoutes::new(authorization_handler, &self.config.server);
        let access_context = routes.access_context_service();
        let address = self.config.access_context_addr();
        let request_timeout = self.config.server.request.timeout;
        let max_in_flight = self.config.server.performance.max_in_flight_requests;
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
        &self,
        supervisor: &mut ServerSupervisor,
        policy: PolicyHandler,
        principals: PrincipalHandler,
        cache: Arc<dyn IAuthorizationCache>,
        metrics: MetricsRegistry,
    ) -> anyhow::Result<()> {
        if !self.config.mgmt.enabled {
            return Ok(());
        }
        let address = self.config.mgmt_addr();
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .with_context(|| format!("bind management listener {address}"))?;
        let routes =
            Self::management_router(policy, principals, cache, metrics, self.config.clone());
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
    async fn open(config: &AuthguardConfig, metrics: MetricsRegistry) -> anyhow::Result<Self> {
        let cache = cache::open(&config.cache).await?;
        tracing::info!(
            authguard.cache.provider = %config.cache.provider,
            "authorization scope cache is ready"
        );
        let repositories = storage::open(&config.storage).await?;
        tracing::info!(
            authguard.storage.provider = %config.storage.provider,
            "authorization storage is ready"
        );
        let principals = PrincipalDiscoveryComponent::new(
            repositories.principals.clone(),
            &config.auth.principal_discovery,
        )?
        .handler();
        let policy = PolicyHandler::open(
            repositories.policy,
            repositories.principals,
            metrics.clone(),
            config.storage.bootstrap_policy.clone(),
        )
        .await?;
        let policy_snapshot = policy.snapshot();
        tracing::info!(
            authguard.policy.revision = policy_snapshot.revision,
            authguard.policy.action_count = policy_snapshot.actions.len(),
            authguard.policy.role_count = policy_snapshot.roles.len(),
            authguard.policy.role_binding_count = policy_snapshot.role_bindings.len(),
            "authorization policy runtime is ready"
        );
        let business_token_signer = Self::open_business_token_signer(&config.auth.business_token)?;
        let authorization = DefaultAuthorizationHandler::new(
            policy.clone(),
            principals.clone(),
            cache.clone(),
            metrics.clone(),
            config.auth.identity.clone(),
            config.auth.scope_delivery.clone(),
            AccessContextSigner::from_env()
                .context("configure direct access-context signing key")?,
            business_token_signer,
        );
        Ok(Self { policy, principals, authorization, cache, metrics })
    }

    /// Opens the RS256 business-token signer from its file-or-inline key.
    ///
    /// Disabled configuration yields `None` and the original identity token is
    /// simply stripped. The private key never leaves this process; business
    /// workloads only hold the paired public key.
    fn open_business_token_signer(
        config: &crate::config::BusinessTokenConfig,
    ) -> anyhow::Result<Option<BusinessTokenSigner>> {
        if !config.enabled {
            return Ok(None);
        }
        let private_key_pem = crate::principal::PrincipalDiscoveryComponent::credential(
            &config.private_key,
            &config.private_key_file,
            "business token RSA private key",
        )?;
        BusinessTokenSigner::new(&private_key_pem)
            .context("configure business token RSA signing key")
            .map(Some)
    }
}

struct PolicyRefreshTask {
    policy: PolicyHandler,
    interval: std::time::Duration,
}

impl PolicyRefreshTask {
    fn new(policy: PolicyHandler, interval: std::time::Duration) -> Self {
        Self { policy, interval }
    }

    async fn run(self, mut shutdown: ServiceShutdown) {
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    match self.policy.refresh_if_newer().await {
                        Ok(_) => {}
                        Err(error) => tracing::warn!(%error, "policy snapshot refresh failed"),
                    }
                }
                requested = shutdown.requested() => {
                    if requested {
                        break;
                    }
                }
            }
        }
    }
}
