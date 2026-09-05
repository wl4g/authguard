use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::model::Policy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthguardConfig {
    pub server: ServerConfig,
    pub mgmt: MgmtConfig,
    pub logging: LoggingConfig,
    pub auth: AuthConfig,
    pub storage: StorageConfig,
    pub cache: CacheConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub service_name: String,
    pub host: IpAddr,
    /// Envoy `ext_authz` Check listener.
    pub port: u16,
    /// Workload SDK opaque scope-token resolver listener.
    pub scope_port: u16,
    #[serde(with = "humantime_serde")]
    pub shutdown_timeout: Duration,
    pub request: RequestConfig,
    pub response: ResponseConfig,
    pub performance: PerformanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RequestConfig {
    pub max_message_bytes: usize,
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponseConfig {
    pub max_message_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PerformanceConfig {
    pub worker_threads: usize,
    pub max_in_flight_requests: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MgmtConfig {
    pub enabled: bool,
    pub host: IpAddr,
    pub port: u16,
    pub context_path: String,
    pub health: HealthConfig,
    pub metrics: MetricsConfig,
    pub otel: OtelConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HealthConfig {
    pub liveness_path: String,
    pub readiness_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OtelConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub protocol: String,
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    pub sample_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    pub mode: String,
    pub level: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub identity: IdentityConfig,
    pub scope_delivery: ScopeDeliveryConfig,
    pub principal_discovery: PrincipalDiscoveryConfig,
    pub admin_token: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrincipalDiscoveryConfig {
    pub jit: JitPrincipalDiscoveryConfig,
    pub federated: FederatedPrincipalDiscoveryConfig,
    pub scim: ScimPrincipalDiscoveryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JitPrincipalDiscoveryConfig {
    pub enabled: bool,
    pub discovery_id: String,
    pub trusted_issuers: Vec<String>,
    pub allow_insecure_http: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FederatedPrincipalDiscoveryConfig {
    pub keycloak: Vec<KeycloakPrincipalDiscoveryConfig>,
    pub ldap: Vec<LdapPrincipalDiscoveryConfig>,
    pub custom: Vec<CustomPrincipalDiscoveryConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeycloakPrincipalDiscoveryConfig {
    pub enabled: bool,
    pub discovery_id: String,
    pub base_url: String,
    pub issuer: String,
    pub realm: String,
    pub client_id: String,
    pub client_secret: String,
    pub client_secret_file: String,
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
    pub max_page_size: u32,
    pub allow_insecure_http: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LdapPrincipalDiscoveryConfig {
    pub enabled: bool,
    pub discovery_id: String,
    pub url: String,
    pub issuer: String,
    pub base_dn: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub bind_password_file: String,
    pub user: LdapObjectMappingConfig,
    pub group: LdapObjectMappingConfig,
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
    pub max_page_size: u32,
    pub allow_insecure: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LdapObjectMappingConfig {
    pub search_base: String,
    pub object_filter: String,
    pub id_attribute: String,
    pub name_attribute: String,
    pub display_name_attribute: Option<String>,
    pub email_attribute: Option<String>,
    pub enabled_attribute: Option<String>,
    pub search_attributes: Vec<String>,
}

/// Serde form of a configurable in-house identity API connector.
///
/// The connector speaks plain HTTP(S) with a static bearer JWT and maps the
/// vendor request/response schema in configuration, so no code is needed to
/// integrate enterprise systems such as an in-house DSP directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CustomPrincipalDiscoveryConfig {
    pub enabled: bool,
    pub discovery_id: String,
    pub url: String,
    pub issuer: String,
    pub jwt_token: String,
    pub jwt_token_file: String,
    pub request: CustomRequestBindingConfig,
    pub response: CustomResponseMappingConfig,
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
    pub max_page_size: u32,
    pub allow_insecure_http: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CustomRequestBindingConfig {
    pub path: String,
    pub text_param: String,
    pub offset_param: String,
    pub limit_param: String,
    pub external_id_param: String,
    pub body_template: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CustomResponseMappingConfig {
    pub array_path: String,
    pub id_attr: String,
    pub display_name_attr: String,
    pub username_attr: Option<String>,
    pub email_attr: Option<String>,
    pub enabled_attr: Option<String>,
    pub kind_attr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScimPrincipalDiscoveryConfig {
    pub enabled: bool,
    pub discovery_id: String,
    pub issuer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScopeDeliveryConfig {
    pub direct_urn_limit: usize,
    pub max_direct_header_bytes: usize,
    #[serde(with = "humantime_serde")]
    pub context_ttl: Duration,
    #[serde(with = "humantime_serde")]
    pub scope_token_ttl: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityConfig {
    pub token_header: String,
    pub issuer_claim: String,
    #[serde(alias = "subject_claim")]
    pub external_id_claim: String,
    pub groups_claim: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub provider: String,
    pub bootstrap_policy: Option<Policy>,
    #[serde(with = "humantime_serde")]
    pub policy_refresh_interval: Duration,
    #[serde(with = "humantime_serde")]
    pub policy_max_staleness: Duration,
    pub sqlite: SqliteConfig,
    pub postgres: PostgresConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheConfig {
    pub provider: String,
    pub memory: MemoryCacheConfig,
    pub redis: RedisClusterConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SqliteConfig {
    pub url: String,
    pub max_connections: u32,
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MemoryCacheConfig {
    pub initial_capacity: usize,
    pub max_capacity: usize,
    #[serde(with = "humantime_serde")]
    pub ttl: Duration,
    pub eviction_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RedisClusterConfig {
    pub nodes: Vec<String>,
    pub username: String,
    pub password: String,
    pub key_prefix: String,
    #[serde(with = "humantime_serde")]
    pub connection_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub response_timeout: Duration,
    pub retries: u32,
    #[serde(with = "humantime_serde")]
    pub max_retry_wait: Duration,
    #[serde(with = "humantime_serde")]
    pub min_retry_wait: Duration,
    pub read_from_replica: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PostgresConfig {
    pub url: String,
    pub max_connections: u32,
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
}

impl AuthguardConfig {
    #[must_use]
    pub fn authorization_addr(&self) -> SocketAddr {
        SocketAddr::new(self.server.host, self.server.port)
    }

    #[must_use]
    pub fn access_context_addr(&self) -> SocketAddr {
        SocketAddr::new(self.server.host, self.server.scope_port)
    }

    #[must_use]
    pub fn mgmt_addr(&self) -> SocketAddr {
        SocketAddr::new(self.mgmt.host, self.mgmt.port)
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            service_name: "authguard".to_string(),
            host: IpAddr::from([0, 0, 0, 0]),
            port: 8080,
            scope_port: 8081,
            shutdown_timeout: Duration::from_secs(15),
            request: RequestConfig::default(),
            response: ResponseConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

impl Default for RequestConfig {
    fn default() -> Self {
        Self { max_message_bytes: 1024 * 1024, timeout: Duration::from_secs(5) }
    }
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self { max_message_bytes: 1024 * 1024 }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self { worker_threads: 2, max_in_flight_requests: 4096 }
    }
}

impl Default for MgmtConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            host: IpAddr::from([0, 0, 0, 0]),
            port: 9091,
            context_path: "/".to_string(),
            health: HealthConfig::default(),
            metrics: MetricsConfig::default(),
            otel: OtelConfig::default(),
        }
    }
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self { liveness_path: "/healthz".to_string(), readiness_path: "/readyz".to_string() }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self { enabled: true, path: "/metrics".to_string() }
    }
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://localhost:4317".to_string(),
            protocol: "grpc".to_string(),
            timeout: Duration::from_secs(5),
            sample_rate: 1.0,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self { mode: "JSON".to_string(), level: "info,tower_http=info".to_string() }
    }
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            token_header: "x-authguard-id-token".to_string(),
            issuer_claim: "iss".to_string(),
            external_id_claim: "sub".to_string(),
            groups_claim: "authguard_group_ids".to_string(),
        }
    }
}

impl Default for JitPrincipalDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            discovery_id: "verified-oidc".to_string(),
            trusted_issuers: vec!["https://idp.example.com/realms/example-corp".to_string()],
            allow_insecure_http: false,
        }
    }
}

impl Default for KeycloakPrincipalDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            discovery_id: String::new(),
            base_url: String::new(),
            issuer: String::new(),
            realm: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            client_secret_file: String::new(),
            connect_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(5),
            max_page_size: 100,
            allow_insecure_http: false,
        }
    }
}

impl Default for LdapPrincipalDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            discovery_id: String::new(),
            url: String::new(),
            issuer: String::new(),
            base_dn: String::new(),
            bind_dn: String::new(),
            bind_password: String::new(),
            bind_password_file: String::new(),
            user: LdapObjectMappingConfig::default(),
            group: LdapObjectMappingConfig::default(),
            connect_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(5),
            max_page_size: 100,
            allow_insecure: false,
        }
    }
}

impl Default for CustomPrincipalDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            discovery_id: String::new(),
            url: String::new(),
            issuer: String::new(),
            jwt_token: String::new(),
            jwt_token_file: String::new(),
            request: CustomRequestBindingConfig::default(),
            response: CustomResponseMappingConfig::default(),
            connect_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(5),
            max_page_size: 100,
            allow_insecure_http: false,
        }
    }
}

impl Default for CustomRequestBindingConfig {
    fn default() -> Self {
        Self {
            path: "/search".to_string(),
            text_param: "search".to_string(),
            offset_param: "offset".to_string(),
            limit_param: "limit".to_string(),
            external_id_param: "id".to_string(),
            body_template: None,
        }
    }
}

impl Default for CustomResponseMappingConfig {
    fn default() -> Self {
        Self {
            array_path: String::new(),
            id_attr: "id".to_string(),
            display_name_attr: "displayName".to_string(),
            username_attr: None,
            email_attr: None,
            enabled_attr: None,
            kind_attr: None,
        }
    }
}

impl Default for ScimPrincipalDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            discovery_id: "corporate-scim".to_string(),
            issuer: "https://idp.example.com/scim/example-corp".to_string(),
        }
    }
}

impl Default for ScopeDeliveryConfig {
    fn default() -> Self {
        Self {
            direct_urn_limit: 32,
            max_direct_header_bytes: 8 * 1024,
            context_ttl: Duration::from_secs(30),
            scope_token_ttl: Duration::from_secs(30),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            provider: "SQLite".to_string(),
            bootstrap_policy: None,
            policy_refresh_interval: Duration::from_secs(5),
            policy_max_staleness: Duration::from_secs(30),
            sqlite: SqliteConfig::default(),
            postgres: PostgresConfig::default(),
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            provider: "Memory".to_string(),
            memory: MemoryCacheConfig::default(),
            redis: RedisClusterConfig::default(),
        }
    }
}

impl Default for SqliteConfig {
    fn default() -> Self {
        Self {
            url: "sqlite://authguard.db?mode=rwc".to_string(),
            max_connections: 1,
            connect_timeout: Duration::from_secs(5),
        }
    }
}

impl Default for MemoryCacheConfig {
    fn default() -> Self {
        Self {
            initial_capacity: 32,
            max_capacity: 65_535,
            ttl: Duration::from_secs(60 * 60),
            eviction_policy: "LRU".to_string(),
        }
    }
}

impl Default for RedisClusterConfig {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            username: String::new(),
            password: String::new(),
            key_prefix: "authguard".to_string(),
            connection_timeout: Duration::from_secs(3),
            response_timeout: Duration::from_secs(6),
            retries: 8,
            max_retry_wait: Duration::from_millis(65_536),
            min_retry_wait: Duration::from_millis(1_280),
            read_from_replica: false,
        }
    }
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self { url: String::new(), max_connections: 20, connect_timeout: Duration::from_secs(5) }
    }
}
