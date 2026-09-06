mod loader;
#[path = "config.rs"]
mod settings;
mod validation;

pub(crate) use loader::secret_env;

pub use settings::{
    AuthConfig, AuthguardConfig, CacheConfig, CustomPrincipalDiscoveryConfig,
    CustomRequestBindingConfig, CustomResponseMappingConfig, HealthConfig, IdentityConfig,
    JitPrincipalDiscoveryConfig, KeycloakPrincipalDiscoveryConfig, LdapBindAuthConfig,
    LdapObjectMappingConfig, LdapPrincipalDiscoveryConfig, LoggingConfig, MemoryCacheConfig,
    MetricsConfig, MgmtConfig, OidcClientCredentialsConfig, OtelConfig, PerformanceConfig,
    PostgresConfig, PrincipalDiscoveryConfig, RedisClusterConfig, RequestConfig, ResignJwtConfig,
    ResponseConfig, ScimPrincipalDiscoveryConfig, ScopeDeliveryConfig, ServerConfig, SqliteConfig,
    StorageConfig,
};

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        AuthguardConfig, CustomPrincipalDiscoveryConfig, KeycloakPrincipalDiscoveryConfig,
        LdapBindAuthConfig, LdapObjectMappingConfig, LdapPrincipalDiscoveryConfig,
        OidcClientCredentialsConfig, PerformanceConfig, ServerConfig,
    };

    #[test]
    fn annotated_default_configuration_is_valid() {
        let config = AuthguardConfig::from_default_yaml().expect("decode defaults");
        config.validate().expect("valid");
        assert_eq!(config.server.service_name, "authguard");
        assert_eq!(config.mgmt.port, 9091);
        assert_eq!(config.storage.provider, "SQLite");
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
        file_storage.storage.provider = "file".to_string();
        assert!(file_storage.validate().is_err());

        let mut file_cache = AuthguardConfig::default();
        file_cache.cache.provider = "File".to_string();
        assert!(file_cache.validate().is_err());
    }

    #[test]
    fn rejects_process_local_providers_in_multi_replica_deployments() {
        let mut memory = AuthguardConfig::default();
        memory.storage.provider = "postgres".to_string();
        assert!(memory.validate_deployment(2).is_err());

        let mut sqlite = AuthguardConfig::default();
        sqlite.cache.provider = "Redis".to_string();
        assert!(sqlite.validate_deployment(2).is_err());

        let mut shared = AuthguardConfig::default();
        shared.storage.provider = "postgres".to_string();
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
        config.auth.principal_discovery.keycloak = vec![KeycloakPrincipalDiscoveryConfig {
            enabled: true,
            discovery_id: "corporate-keycloak".to_string(),
            base_url: "https://id.example.com".to_string(),
            issuer: "https://id.example.com/realms/corporate".to_string(),
            realm: "corporate".to_string(),
            auth: OidcClientCredentialsConfig {
                client_id: "authguard-principal-discovery".to_string(),
                client_secret_file: "/run/secrets/keycloak-client-secret".to_string(),
                ..OidcClientCredentialsConfig::default()
            },
            ..KeycloakPrincipalDiscoveryConfig::default()
        }];
        let object_mapping = LdapObjectMappingConfig {
            object_filter: "(objectClass=inetOrgPerson)".to_string(),
            id_attribute: "entryUUID".to_string(),
            name_attribute: "uid".to_string(),
            search_attributes: vec!["uid".to_string(), "mail".to_string()],
            ..LdapObjectMappingConfig::default()
        };
        config.auth.principal_discovery.ldap = vec![LdapPrincipalDiscoveryConfig {
            enabled: true,
            discovery_id: "corporate-ldap".to_string(),
            url: "ldaps://ldap.example.com:636".to_string(),
            issuer: "urn:identity:corporate-ldap".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            auth: LdapBindAuthConfig {
                bind_dn: "cn=authguard,ou=service-accounts,dc=example,dc=com".to_string(),
                bind_password_file: "/run/secrets/ldap-bind-password".to_string(),
                ..LdapBindAuthConfig::default()
            },
            user: object_mapping.clone(),
            group: LdapObjectMappingConfig {
                object_filter: "(objectClass=groupOfNames)".to_string(),
                name_attribute: "cn".to_string(),
                search_attributes: vec!["cn".to_string()],
                ..object_mapping
            },
            ..LdapPrincipalDiscoveryConfig::default()
        }];
        config.auth.principal_discovery.custom = vec![CustomPrincipalDiscoveryConfig {
            enabled: true,
            discovery_id: "dsp-directory".to_string(),
            url: "https://dsp.example.com/identity".to_string(),
            issuer: "https://dsp.example.com".to_string(),
            jwt_token_file: "/run/secrets/dsp-jwt".to_string(),
            ..CustomPrincipalDiscoveryConfig::default()
        }];

        config.validate().expect("file-backed connector credentials are valid");

        config.auth.principal_discovery.keycloak[0].auth.client_secret =
            "ambiguous-inline-secret".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn skips_disabled_federated_connector_entries() {
        let mut config = AuthguardConfig::default();
        // Incomplete on purpose: a disabled entry must not be validated.
        config.auth.principal_discovery.keycloak =
            vec![KeycloakPrincipalDiscoveryConfig::default()];
        config.auth.principal_discovery.ldap = vec![LdapPrincipalDiscoveryConfig::default()];
        config.auth.principal_discovery.custom = vec![CustomPrincipalDiscoveryConfig::default()];

        config.validate().expect("disabled federated entries are skipped");
    }

    #[test]
    fn rejects_multiple_enabled_connectors_of_one_protocol() {
        let keycloak = |discovery_id: &str| KeycloakPrincipalDiscoveryConfig {
            enabled: true,
            discovery_id: discovery_id.to_string(),
            base_url: "https://sso.example.com".to_string(),
            realm: "example-corp".to_string(),
            auth: OidcClientCredentialsConfig {
                client_id: "authguard-search".to_string(),
                client_secret: "not-logged-secret".to_string(),
                ..OidcClientCredentialsConfig::default()
            },
            ..KeycloakPrincipalDiscoveryConfig::default()
        };

        // Two enabled connectors of the same protocol are ambiguous by
        // definition: search candidates must map to exactly one source.
        let mut config = AuthguardConfig::default();
        config.auth.principal_discovery.keycloak =
            vec![keycloak("corporate-keycloak"), keycloak("partner-keycloak")];
        assert!(config.validate().is_err());

        // One per protocol stays valid and unambiguous.
        config.auth.principal_discovery.keycloak = vec![keycloak("corporate-keycloak")];
        config.validate().expect("one enabled connector per protocol is valid");
    }

    #[test]
    fn validates_resign_jwt_configuration() {
        let mut config = AuthguardConfig::default();
        config.validate().expect("resign JWT is disabled by default");

        config.auth.resign_jwt.enabled = true;
        config.auth.resign_jwt.private_key = "not a real key".to_string();
        config.auth.resign_jwt.ttl = Duration::ZERO;
        assert!(config.validate().is_err(), "positive ttl is required");

        config.auth.resign_jwt.ttl = Duration::from_secs(60);
        config.validate().expect("inline private key is valid");

        config.auth.resign_jwt.private_key_file = "/run/secrets/resign-jwt-key".to_string();
        assert!(config.validate().is_err(), "exactly one key source is required");

        config.auth.resign_jwt.private_key.clear();
        config.validate().expect("file-backed private key is valid");
    }
}
