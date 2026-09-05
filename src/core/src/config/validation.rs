use anyhow::bail;

use super::{
    AuthguardConfig, CacheConfig, CustomPrincipalDiscoveryConfig, IdentityConfig,
    JitPrincipalDiscoveryConfig, KeycloakPrincipalDiscoveryConfig, LdapPrincipalDiscoveryConfig,
    MgmtConfig, PrincipalDiscoveryConfig, RedisClusterConfig, ScimPrincipalDiscoveryConfig,
    ScopeDeliveryConfig, ServerConfig, StorageConfig,
};

impl AuthguardConfig {
    /// Validates limits and paths before listeners or exporters are started.
    ///
    /// # Errors
    ///
    /// Returns a descriptive error for invalid or unsafe limits.
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_server(&self.server)?;
        validate_management(&self.mgmt)?;
        validate_scope_delivery(&self.auth.scope_delivery)?;
        validate_identity(&self.auth.identity)?;
        validate_principal_discovery(&self.auth.principal_discovery)?;
        validate_storage(&self.storage)?;
        validate_cache(&self.cache)?;
        Ok(())
    }

    /// Validates deployment topology constraints that are not represented by
    /// the process-local YAML configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when a process-local storage or cache provider is used
    /// by more than one Authguard replica.
    pub fn validate_deployment(&self, replica_count: usize) -> anyhow::Result<()> {
        if replica_count == 0 {
            bail!("AUTHGUARD_REPLICA_COUNT must be positive");
        }
        if replica_count > 1 && self.storage.provider.eq_ignore_ascii_case("SQLite") {
            bail!(
                "storage.provider=SQLite supports only one Authguard replica; use PostgreSQL for multi-replica deployments"
            );
        }
        if replica_count > 1 && self.cache.provider.eq_ignore_ascii_case("memory") {
            bail!(
                "cache.provider=Memory supports only one Authguard replica; use Redis for multi-replica scope-token delivery"
            );
        }
        Ok(())
    }
}

fn validate_server(server: &ServerConfig) -> anyhow::Result<()> {
    if server.service_name.trim().is_empty() {
        bail!("server.service_name must not be empty");
    }
    if server.port == 0 || server.scope_port == 0 || server.port == server.scope_port {
        bail!("server.port and server.scope_port must be distinct non-zero ports");
    }
    if !(1024..=64 * 1024 * 1024).contains(&server.request.max_message_bytes) {
        bail!("server.request.max_message_bytes must be between 1 KiB and 64 MiB");
    }
    if !(1024..=64 * 1024 * 1024).contains(&server.response.max_message_bytes) {
        bail!("server.response.max_message_bytes must be between 1 KiB and 64 MiB");
    }
    if !(1..=256).contains(&server.performance.worker_threads) {
        bail!("server.performance.worker_threads must be between 1 and 256");
    }
    if server.performance.max_in_flight_requests == 0 {
        bail!("server.performance.max_in_flight_requests must be positive");
    }
    if server.request.timeout.is_zero() || server.shutdown_timeout.is_zero() {
        bail!("server timeouts must be positive");
    }
    Ok(())
}

fn validate_management(mgmt: &MgmtConfig) -> anyhow::Result<()> {
    validate_context_path("mgmt.context_path", &mgmt.context_path)?;
    validate_endpoint_path("mgmt.health.liveness_path", &mgmt.health.liveness_path)?;
    validate_endpoint_path("mgmt.health.readiness_path", &mgmt.health.readiness_path)?;
    validate_endpoint_path("mgmt.metrics.path", &mgmt.metrics.path)?;
    if !mgmt.otel.enabled {
        return Ok(());
    }
    if mgmt.otel.endpoint.trim().is_empty() {
        bail!("mgmt.otel.endpoint is required when OTel is enabled");
    }
    if mgmt.otel.protocol != "grpc" {
        bail!("mgmt.otel.protocol currently supports only grpc");
    }
    if !(0.0..=1.0).contains(&mgmt.otel.sample_rate) {
        bail!("mgmt.otel.sample_rate must be between 0 and 1");
    }
    if mgmt.otel.timeout.is_zero() {
        bail!("mgmt.otel.timeout must be positive");
    }
    Ok(())
}

fn validate_scope_delivery(delivery: &ScopeDeliveryConfig) -> anyhow::Result<()> {
    if delivery.direct_urn_limit == 0 {
        bail!("auth.scope_delivery.direct_urn_limit must be positive");
    }
    if !(1024..=64 * 1024).contains(&delivery.max_direct_header_bytes) {
        bail!("auth.scope_delivery.max_direct_header_bytes must be between 1 KiB and 64 KiB");
    }
    if delivery.context_ttl.is_zero() || delivery.scope_token_ttl.is_zero() {
        bail!("auth.scope_delivery TTLs must be positive");
    }
    Ok(())
}

fn validate_identity(identity: &IdentityConfig) -> anyhow::Result<()> {
    if identity.token_header.trim().is_empty()
        || identity.issuer_claim.trim().is_empty()
        || identity.external_id_claim.trim().is_empty()
        || identity.groups_claim.trim().is_empty()
    {
        bail!("auth.identity token header and claim names must not be empty");
    }
    Ok(())
}

fn validate_principal_discovery(config: &PrincipalDiscoveryConfig) -> anyhow::Result<()> {
    validate_jit(&config.jit)?;
    for keycloak in config.federated.keycloak.iter().filter(|entry| entry.enabled) {
        validate_keycloak(keycloak)?;
    }
    for ldap in config.federated.ldap.iter().filter(|entry| entry.enabled) {
        validate_ldap(ldap)?;
    }
    for custom in config.federated.custom.iter().filter(|entry| entry.enabled) {
        validate_custom(custom)?;
    }
    validate_scim(&config.jit, &config.scim)
}

fn validate_jit(jit: &JitPrincipalDiscoveryConfig) -> anyhow::Result<()> {
    if jit.enabled && (jit.discovery_id.trim().is_empty() || jit.trusted_issuers.is_empty()) {
        bail!("auth.principal_discovery.jit requires discovery_id and trusted_issuers");
    }
    Ok(())
}

fn validate_keycloak(keycloak: &KeycloakPrincipalDiscoveryConfig) -> anyhow::Result<()> {
    if keycloak.discovery_id.trim().is_empty()
        || keycloak.base_url.trim().is_empty()
        || keycloak.realm.trim().is_empty()
        || keycloak.client_id.trim().is_empty()
        || (keycloak.client_secret.is_empty() == keycloak.client_secret_file.is_empty())
    {
        bail!(
            "each Keycloak principal discovery requires id, URL, realm and exactly one of client_secret or client_secret_file"
        );
    }
    if keycloak.connect_timeout.is_zero()
        || keycloak.request_timeout.is_zero()
        || keycloak.max_page_size == 0
    {
        bail!("Keycloak principal discovery timeouts and max_page_size must be positive");
    }
    Ok(())
}

fn validate_ldap(ldap: &LdapPrincipalDiscoveryConfig) -> anyhow::Result<()> {
    if ldap.discovery_id.trim().is_empty()
        || ldap.url.trim().is_empty()
        || ldap.issuer.trim().is_empty()
        || ldap.base_dn.trim().is_empty()
        || ldap.bind_dn.trim().is_empty()
        || (ldap.bind_password.is_empty() == ldap.bind_password_file.is_empty())
    {
        bail!(
            "each LDAP principal discovery requires id, URL, issuer, base DN and exactly one of bind_password or bind_password_file"
        );
    }
    if ldap.connect_timeout.is_zero() || ldap.request_timeout.is_zero() || ldap.max_page_size == 0 {
        bail!("LDAP principal discovery timeouts and max_page_size must be positive");
    }
    for (kind, mapping) in [("user", &ldap.user), ("group", &ldap.group)] {
        if mapping.object_filter.trim().is_empty()
            || mapping.id_attribute.trim().is_empty()
            || mapping.name_attribute.trim().is_empty()
            || mapping.search_attributes.is_empty()
        {
            bail!(
                "LDAP {kind} mapping requires object_filter, id_attribute, name_attribute and search_attributes"
            );
        }
    }
    Ok(())
}

fn validate_custom(custom: &CustomPrincipalDiscoveryConfig) -> anyhow::Result<()> {
    if custom.discovery_id.trim().is_empty()
        || custom.url.trim().is_empty()
        || custom.issuer.trim().is_empty()
        || (custom.jwt_token.is_empty() == custom.jwt_token_file.is_empty())
    {
        bail!(
            "each custom principal discovery requires id, URL, issuer and exactly one of jwt_token or jwt_token_file"
        );
    }
    if custom.request.path.trim().is_empty()
        || custom.request.text_param.trim().is_empty()
        || custom.request.offset_param.trim().is_empty()
        || custom.request.limit_param.trim().is_empty()
        || custom.request.external_id_param.trim().is_empty()
        || custom.response.id_attr.trim().is_empty()
        || custom.response.display_name_attr.trim().is_empty()
    {
        bail!(
            "custom principal discovery requires request path, query parameter names and response id/display-name attributes"
        );
    }
    if custom.connect_timeout.is_zero()
        || custom.request_timeout.is_zero()
        || custom.max_page_size == 0
    {
        bail!("custom principal discovery timeouts and max_page_size must be positive");
    }
    Ok(())
}

fn validate_scim(
    jit: &JitPrincipalDiscoveryConfig,
    scim: &ScimPrincipalDiscoveryConfig,
) -> anyhow::Result<()> {
    if scim.enabled && (scim.discovery_id.trim().is_empty() || scim.issuer.trim().is_empty()) {
        bail!("auth.principal_discovery.scim requires discovery_id and issuer");
    }
    if scim.enabled
        && jit.enabled
        && !jit.trusted_issuers.iter().any(|issuer| issuer == &scim.issuer)
    {
        bail!(
            "auth.principal_discovery.scim.issuer must exactly match a trusted OIDC issuer so SCIM and JIT converge on one Principal"
        );
    }
    Ok(())
}

fn validate_storage(storage: &StorageConfig) -> anyhow::Result<()> {
    if storage.policy_refresh_interval.is_zero() {
        bail!("storage.policy_refresh_interval must be positive");
    }
    if storage.policy_max_staleness < storage.policy_refresh_interval {
        bail!("storage.policy_max_staleness must be at least policy_refresh_interval");
    }
    match storage.provider.to_ascii_lowercase().as_str() {
        "sqlite" if storage.sqlite.url.trim().is_empty() => {
            bail!("storage.sqlite.url is required for the sqlite provider");
        }
        "sqlite" if storage.sqlite.max_connections == 0 => {
            bail!("storage.sqlite.max_connections must be positive");
        }
        "sqlite" if storage.sqlite.connect_timeout.is_zero() => {
            bail!("storage.sqlite.connect_timeout must be positive");
        }
        "postgres" if storage.postgres.url.trim().is_empty() => {
            bail!("storage.postgres.url is required for the postgres provider");
        }
        "postgres" if storage.postgres.max_connections == 0 => {
            bail!("storage.postgres.max_connections must be positive");
        }
        "postgres" if storage.postgres.connect_timeout.is_zero() => {
            bail!("storage.postgres.connect_timeout must be positive");
        }
        "sqlite" | "postgres" => {}
        provider => bail!("storage.provider must be SQLite or postgres, got `{provider}`"),
    }
    Ok(())
}

fn validate_cache(cache: &CacheConfig) -> anyhow::Result<()> {
    match cache.provider.to_ascii_lowercase().as_str() {
        "memory" => {}
        "redis" | "redis_cluster" => validate_redis_cache(&cache.redis)?,
        provider => bail!("cache.provider must be Memory or Redis, got `{provider}`"),
    }
    if cache.memory.initial_capacity > cache.memory.max_capacity || cache.memory.max_capacity == 0 {
        bail!("cache.memory capacity must be positive and initial_capacity <= max_capacity");
    }
    if cache.memory.ttl.is_zero() {
        bail!("cache.memory.ttl must be positive");
    }
    if !cache.memory.eviction_policy.eq_ignore_ascii_case("LRU") {
        bail!("cache.memory.eviction_policy currently supports only LRU");
    }
    Ok(())
}

fn validate_redis_cache(redis: &RedisClusterConfig) -> anyhow::Result<()> {
    if redis.nodes.is_empty() {
        bail!("cache.redis.nodes is required");
    }
    if redis.key_prefix.trim().is_empty() {
        bail!("cache.redis.key_prefix must not be empty");
    }
    if redis.connection_timeout.is_zero() || redis.response_timeout.is_zero() {
        bail!("cache.redis timeouts must be positive");
    }
    if redis.min_retry_wait > redis.max_retry_wait {
        bail!("cache.redis.min_retry_wait must not exceed max_retry_wait");
    }
    if redis.read_from_replica {
        bail!(
            "cache.redis.read_from_replica must be false because scope-token resolution requires read-after-write consistency"
        );
    }
    Ok(())
}

fn validate_context_path(name: &str, path: &str) -> anyhow::Result<()> {
    if !path.starts_with('/') || path.len() > 1 && path.ends_with('/') {
        bail!("{name} must start with / and must not end with /");
    }
    Ok(())
}

fn validate_endpoint_path(name: &str, path: &str) -> anyhow::Result<()> {
    if !path.starts_with('/') {
        bail!("{name} must start with /");
    }
    Ok(())
}
