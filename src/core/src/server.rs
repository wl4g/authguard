use std::{future::Future, sync::Arc, time::Duration};

use anyhow::{anyhow, Context as _};
use axum::Router;
use tonic::transport::Server;

use crate::cache::{self, IAuthorizationCache};
use crate::config::AuthguardConfig;
use crate::handler::{
    DefaultAuthorizationHandler, ManagementHandler, PolicyHandler, PrincipalHandler,
};
use crate::model::AccessContextSigner;
use crate::principal::{
    CustomPrincipalDiscovery, CustomPrincipalDiscoveryConfig, CustomRequestBinding,
    CustomResponseMapping, IPrincipalDiscovery, JitPrincipalDiscovery, KeycloakPrincipalDiscovery,
    KeycloakPrincipalDiscoveryConfig, LdapObjectMapping, LdapPrincipalDiscovery,
    LdapPrincipalDiscoveryConfig, PrincipalDiscoveryError, PrincipalSearchDiscovery,
    PrincipalSearchPage, PrincipalSearchQuery, ScimPrincipalDiscovery,
};
use crate::route::{AuthorizationRoutes, ManagementRoutes};
use crate::storage;
use crate::utils::{init_telemetry, MetricsRegistry};

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
        let telemetry = init_telemetry(&self.config.telemetry_config())?;
        tracing::info!(
            service.name = %self.config.server.service_name,
            authguard.storage.provider = %self.config.storage.provider,
            authguard.cache.provider = %self.config.cache.provider,
            authguard.management.enabled = self.config.mgmt.enabled,
            authguard.principal.jit_enabled = self.config.auth.principal_discovery.jit.enabled,
            authguard.principal.federated_provider_count =
                self.config.auth.principal_discovery.federated.keycloak.len()
                    + self.config.auth.principal_discovery.federated.ldap.len()
                    + self.config.auth.principal_discovery.federated.custom.len(),
            authguard.principal.scim_enabled = self.config.auth.principal_discovery.scim.enabled,
            "starting Authguard runtime"
        );
        let runtime = RuntimeComponents::open(&self.config).await?;
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
        telemetry.shutdown();
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
    /// Adds one search provider, rejecting duplicate protocol identifiers.
    ///
    /// Each `FED_KEYCLOAK`/`FED_LDAP` protocol must be configured at most
    /// once, because search filtering and resolution dispatch on the
    /// protocol identifier.
    fn push_search_provider<T>(
        providers: &mut Vec<Arc<PrincipalSearchDiscovery>>,
        provider: T,
    ) -> anyhow::Result<()>
    where
        T: IPrincipalDiscovery<PrincipalSearchQuery, Output = PrincipalSearchPage>,
    {
        let protocol = provider.provider();
        if providers.iter().any(|existing| existing.provider() == protocol) {
            anyhow::bail!(PrincipalDiscoveryError::InvalidConfiguration(format!(
                "search provider protocol `{protocol}` is already configured"
            )));
        }
        providers.push(Arc::new(provider));
        Ok(())
    }

    async fn open(config: &AuthguardConfig) -> anyhow::Result<Self> {
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
        let metrics = MetricsRegistry::default();
        let jit = config
            .auth
            .principal_discovery
            .jit
            .enabled
            .then(|| {
                let jit = &config.auth.principal_discovery.jit;
                JitPrincipalDiscovery::new(
                    jit.discovery_id.clone(),
                    jit.trusted_issuers.clone(),
                    jit.allow_insecure_http,
                )
            })
            .transpose()
            .context("configure OIDC JIT Principal discovery")?;
        let mut discoveries: Vec<Arc<PrincipalSearchDiscovery>> = Vec::new();
        for keycloak in &config.auth.principal_discovery.federated.keycloak {
            let mut provider = KeycloakPrincipalDiscoveryConfig::new(
                keycloak.discovery_id.clone(),
                keycloak.base_url.clone(),
                keycloak.realm.clone(),
            );
            provider.issuer_url = (!keycloak.issuer.is_empty()).then(|| keycloak.issuer.clone());
            provider.connect_timeout = keycloak.connect_timeout;
            provider.request_timeout = keycloak.request_timeout;
            provider.max_page_size = keycloak.max_page_size;
            provider.allow_insecure_http = keycloak.allow_insecure_http;
            let provider = KeycloakPrincipalDiscovery::with_client_credentials(
                provider,
                keycloak.client_id.clone(),
                Self::credential(
                    &keycloak.client_secret,
                    &keycloak.client_secret_file,
                    "Keycloak client secret",
                )?,
            )
            .context("configure Keycloak Principal discovery")?;
            Self::push_search_provider(&mut discoveries, provider)?;
        }
        for ldap in &config.auth.principal_discovery.federated.ldap {
            let object_mapping = |mapping: &crate::config::LdapObjectMappingConfig| {
                let mut mapped = LdapObjectMapping::new(
                    mapping.search_base.clone(),
                    mapping.object_filter.clone(),
                    mapping.id_attribute.clone(),
                    mapping.name_attribute.clone(),
                    mapping.search_attributes.clone(),
                );
                mapped.display_name_attribute = mapping.display_name_attribute.clone();
                mapped.email_attribute = mapping.email_attribute.clone();
                mapped.enabled_attribute = mapping.enabled_attribute.clone();
                mapped
            };
            let mut provider = LdapPrincipalDiscoveryConfig::new(
                ldap.discovery_id.clone(),
                ldap.url.clone(),
                ldap.issuer.clone(),
                ldap.base_dn.clone(),
                ldap.bind_dn.clone(),
                Self::credential(
                    &ldap.bind_password,
                    &ldap.bind_password_file,
                    "LDAP bind password",
                )?,
                object_mapping(&ldap.user),
                object_mapping(&ldap.group),
            );
            provider.connect_timeout = ldap.connect_timeout;
            provider.request_timeout = ldap.request_timeout;
            provider.max_page_size = ldap.max_page_size;
            provider.allow_insecure = ldap.allow_insecure;
            let provider = LdapPrincipalDiscovery::new(provider)
                .context("configure LDAP Principal discovery")?;
            Self::push_search_provider(&mut discoveries, provider)?;
        }
        for custom in &config.auth.principal_discovery.federated.custom {
            let request = CustomRequestBinding {
                path: custom.request.path.clone(),
                text_param: custom.request.text_param.clone(),
                offset_param: custom.request.offset_param.clone(),
                limit_param: custom.request.limit_param.clone(),
                external_id_param: custom.request.external_id_param.clone(),
                body_template: custom.request.body_template.clone(),
            };
            let response = CustomResponseMapping {
                array_path: custom.response.array_path.clone(),
                id_attr: custom.response.id_attr.clone(),
                display_name_attr: custom.response.display_name_attr.clone(),
                username_attr: custom.response.username_attr.clone(),
                email_attr: custom.response.email_attr.clone(),
                enabled_attr: custom.response.enabled_attr.clone(),
                kind_attr: custom.response.kind_attr.clone(),
            };
            let mut provider = CustomPrincipalDiscoveryConfig::new(
                custom.discovery_id.clone(),
                custom.url.clone(),
                custom.issuer.clone(),
                Self::credential(
                    &custom.jwt_token,
                    &custom.jwt_token_file,
                    "custom JWT token",
                )?,
                request,
                response,
            );
            provider.connect_timeout = custom.connect_timeout;
            provider.request_timeout = custom.request_timeout;
            provider.max_page_size = custom.max_page_size;
            provider.allow_insecure_http = custom.allow_insecure_http;
            let provider = CustomPrincipalDiscovery::new(provider)
                .context("configure custom Principal discovery")?;
            Self::push_search_provider(&mut discoveries, provider)?;
        }
        let federated_provider_count = discoveries.len();
        let scim = config
            .auth
            .principal_discovery
            .scim
            .enabled
            .then(|| {
                let scim = &config.auth.principal_discovery.scim;
                ScimPrincipalDiscovery::new(scim.discovery_id.clone(), scim.issuer.clone())
            })
            .transpose()
            .context("configure SCIM Principal discovery")?;
        let principals =
            PrincipalHandler::new(repositories.principals.clone(), jit, discoveries, scim);
        tracing::info!(
            authguard.principal.jit_enabled = config.auth.principal_discovery.jit.enabled,
            authguard.principal.federated_provider_count = federated_provider_count,
            authguard.principal.scim_enabled = config.auth.principal_discovery.scim.enabled,
            "principal discovery providers configured"
        );
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
        let authorization = DefaultAuthorizationHandler::new(
            policy.clone(),
            principals.clone(),
            cache.clone(),
            metrics.clone(),
            config.auth.identity.clone(),
            config.auth.scope_delivery.clone(),
            AccessContextSigner::from_env()
                .context("configure direct access-context signing key")?,
        );
        Ok(Self { policy, principals, authorization, cache, metrics })
    }

    fn credential(value: &str, file: &str, name: &str) -> anyhow::Result<String> {
        if !value.is_empty() {
            return Ok(value.to_string());
        }
        let value = std::fs::read_to_string(file)
            .with_context(|| format!("read {name} file"))?
            .trim_end_matches(['\r', '\n'])
            .to_string();
        if value.is_empty() {
            return Err(anyhow!("{name} file is empty"));
        }
        Ok(value)
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
