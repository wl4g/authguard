mod loader;
#[path = "config.rs"]
mod settings;
mod validation;

pub use settings::{
    AuthConfig, AuthguardConfig, CacheConfig, FederatedPrincipalDiscoveryConfig, HealthConfig,
    IdentityConfig, JitPrincipalDiscoveryConfig, KeycloakPrincipalDiscoveryConfig,
    LdapObjectMappingConfig, LdapPrincipalDiscoveryConfig, LoggingConfig, MemoryCacheConfig,
    MetricsConfig, MgmtConfig, OtelConfig, PerformanceConfig, PostgresConfig,
    PrincipalDiscoveryConfig, RedisClusterConfig, RequestConfig, ResponseConfig,
    ScimPrincipalDiscoveryConfig, ScopeDeliveryConfig, ServerConfig, SqliteConfig, StorageConfig,
};

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        AuthguardConfig, KeycloakPrincipalDiscoveryConfig, LdapObjectMappingConfig,
        LdapPrincipalDiscoveryConfig, PerformanceConfig, ServerConfig,
    };

    #[test]
    fn annotated_default_configuration_is_valid() {
        let config = AuthguardConfig::from_default_yaml().expect("decode defaults");
        config.validate().expect("valid");
        assert_eq!(config.server.service_name, "authguard");
        assert_eq!(config.mgmt.port, 9091);
        assert_eq!(config.storage.backend, "sqlite");
        assert_eq!(config.cache.provider, "Memory");
        assert_eq!(config.cache.memory.max_capacity, 65_535);
    }

    #[test]
    fn rejects_unbounded_worker_configuration() {
        let config = AuthguardConfig {
            server: ServerConfig {
                performance: PerformanceConfig {
                    worker_threads: 0,
                    ..PerformanceConfig::default()
                },
                ..ServerConfig::default()
            },
            ..AuthguardConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_removed_file_storage_and_cache_providers() {
        let mut file_storage = AuthguardConfig::default();
        file_storage.storage.backend = "file".to_string();
        assert!(file_storage.validate().is_err());

        let mut file_cache = AuthguardConfig::default();
        file_cache.cache.provider = "File".to_string();
        assert!(file_cache.validate().is_err());
    }

    #[test]
    fn rejects_process_local_backends_in_multi_replica_deployments() {
        let mut memory = AuthguardConfig::default();
        memory.storage.backend = "postgres".to_string();
        assert!(memory.validate_deployment(2).is_err());

        let mut sqlite = AuthguardConfig::default();
        sqlite.cache.provider = "Redis".to_string();
        assert!(sqlite.validate_deployment(2).is_err());

        let mut shared = AuthguardConfig::default();
        shared.storage.backend = "postgres".to_string();
        shared.cache.provider = "Redis".to_string();
        assert!(shared.validate_deployment(2).is_ok());
        assert!(shared.validate_deployment(0).is_err());
    }

    #[test]
    fn rejects_redis_replica_reads_for_scope_tokens() {
        let mut config = AuthguardConfig::default();
        config.cache.provider = "Redis".to_string();
        config.cache.redis.read_from_replica = true;

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_policy_staleness_shorter_than_the_refresh_interval() {
        let mut config = AuthguardConfig::default();
        config.storage.policy_refresh_interval = Duration::from_secs(10);
        config.storage.policy_max_staleness = Duration::from_secs(9);

        assert!(config.validate().is_err());
    }

    #[test]
    fn validates_file_backed_federated_discovery_credentials() {
        let mut config = AuthguardConfig::default();
        config.auth.principal_discovery.federated.keycloak =
            vec![KeycloakPrincipalDiscoveryConfig {
                discovery_id: "corporate-keycloak".to_string(),
                base_url: "https://id.example.com".to_string(),
                issuer: "https://id.example.com/realms/corporate".to_string(),
                realm: "corporate".to_string(),
                client_id: "authguard-principal-discovery".to_string(),
                client_secret_file: "/run/secrets/keycloak-client-secret".to_string(),
                ..KeycloakPrincipalDiscoveryConfig::default()
            }];
        let object_mapping = LdapObjectMappingConfig {
            object_filter: "(objectClass=inetOrgPerson)".to_string(),
            id_attribute: "entryUUID".to_string(),
            name_attribute: "uid".to_string(),
            search_attributes: vec!["uid".to_string(), "mail".to_string()],
            ..LdapObjectMappingConfig::default()
        };
        config.auth.principal_discovery.federated.ldap = vec![LdapPrincipalDiscoveryConfig {
            discovery_id: "corporate-ldap".to_string(),
            url: "ldaps://ldap.example.com:636".to_string(),
            issuer: "urn:identity:corporate-ldap".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: "cn=authguard,ou=service-accounts,dc=example,dc=com".to_string(),
            bind_password_file: "/run/secrets/ldap-bind-password".to_string(),
            user: object_mapping.clone(),
            group: LdapObjectMappingConfig {
                object_filter: "(objectClass=groupOfNames)".to_string(),
                name_attribute: "cn".to_string(),
                search_attributes: vec!["cn".to_string()],
                ..object_mapping
            },
            ..LdapPrincipalDiscoveryConfig::default()
        }];

        config.validate().expect("file-backed connector credentials are valid");

        config.auth.principal_discovery.federated.keycloak[0].client_secret =
            "ambiguous-inline-secret".to_string();
        assert!(config.validate().is_err());
    }
}
