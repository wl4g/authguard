//! One strongly typed product configuration shared by `AuthN` and `AuthZ`.
//!
//! Startup precedence is Spring Boot-like and uses schema-agnostic YAML traversal:
//! built-in defaults < authguard.yaml < AUTHGUARD__... environment values.
//! Double underscores address arbitrary nested properties, for example
//! `AUTHGUARD__AUTHN__SESSION__AUDIENCE` and
//! `AUTHGUARD__STORAGE__POSTGRES__MAX_CONNECTIONS`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use anyhow::{bail, Context as _};
use config::{Config, File, FileFormat};
use serde::{Deserialize, Serialize};

use super::constants::{
    CONFIG_FILE_ENV, DEFAULT_CONFIG, DEFAULT_CONFIG_YAML, ENV_PREFIX, SECRET_ENV_FILE_ENV,
};
use crate::model::IamPolicyInfo;

/// Complete product configuration shared by `AuthN` and `AuthZ`.
///
/// Fields intentionally run from common infrastructure to product-specific
/// modules so the YAML hierarchy and Rust model have the same shape.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppConfigProperties {
    pub server: ServerProperties,
    pub mgmt: ManagementProperties,
    pub logging: LoggingProperties,
    pub cache: CacheProperties,
    pub storage: StorageProperties,
    pub authn: AuthnProperties,
    pub authz: AuthzProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerProperties {
    pub service_name: String,
    pub host: IpAddr,
    /// Envoy `ext_authz` Check listener.
    pub port: u16,
    /// Workload SDK opaque scope-token resolver listener.
    pub scope_port: u16,
    #[serde(with = "humantime_serde")]
    pub shutdown_timeout: Duration,
    pub request: RequestProperties,
    pub response: ResponseProperties,
    pub performance: PerformanceProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RequestProperties {
    pub max_message_bytes: usize,
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponseProperties {
    pub max_message_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PerformanceProperties {
    pub worker_threads: usize,
    pub max_in_flight_requests: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ManagementProperties {
    pub enabled: bool,
    pub host: IpAddr,
    pub port: u16,
    pub context_path: String,
    pub health: HealthProperties,
    pub metrics: MetricsProperties,
    pub otel: OtelProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HealthProperties {
    pub liveness_path: String,
    pub readiness_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsProperties {
    pub enabled: bool,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OtelProperties {
    pub enabled: bool,
    pub endpoint: String,
    pub protocol: String,
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    pub sample_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingProperties {
    pub mode: String,
    pub level: String,
}

/// Shared cache backend selection. The stored value semantics are defined by
/// the owning feature (currently opaque `AuthZ` access contexts).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheProperties {
    pub provider: String,
    pub memory: MemoryCacheProperties,
    pub redis: RedisClusterProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MemoryCacheProperties {
    pub initial_capacity: usize,
    pub max_capacity: usize,
    #[serde(with = "humantime_serde")]
    pub ttl: Duration,
    pub eviction_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RedisClusterProperties {
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
pub struct StorageProperties {
    pub provider: String,
    pub bootstrap_policy: Option<IamPolicyInfo>,
    pub sqlite: SqliteProperties,
    pub postgres: PostgresProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SqliteProperties {
    pub url: String,
    pub max_connections: u32,
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PostgresProperties {
    pub url: String,
    pub username: String,
    pub password: String,
    pub max_connections: u32,
    pub min_connections: u32,
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,
    pub validate_on_acquire: bool,
}

/// Authentication protocol details only; account governance is centralized
/// under `account_linking`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthnProperties {
    pub providers: BTreeMap<String, ProviderProperties>,
    #[serde(rename = "accountLinking")]
    pub account_linking: AccountLinkingProperties,
    pub session: SessionProperties,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProviderProperties {
    #[serde(rename = "oidc")]
    Oidc(OidcProviderProperties),
    #[serde(rename = "oauth2")]
    OAuth2(OAuthProviderProperties),
    #[serde(rename = "oauth2-like")]
    OAuth2Like(OAuthProviderProperties),
    #[serde(rename = "custom")]
    Custom(CustomProviderProperties),
}

/// Standard `OpenID` Connect Authorization Code flow discovered from `issuer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OidcProviderProperties {
    pub issuer: String,
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "clientSecret")]
    pub client_secret: String,
    #[serde(rename = "callbackUrl")]
    pub callback_url: String,
    pub scopes: Vec<String>,
    pub userinfo: bool,
    #[serde(rename = "tokenIntrospection")]
    pub token_introspection: Option<TokenIntrospectionProperties>,
    pub identity: IdentityMappingProperties,
}

/// RFC 7662 validation used when an external bearer token is translated into
/// an `AuthGuard` canonical token. It is optional for browser-only OIDC login.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TokenIntrospectionProperties {
    pub endpoint: String,
    #[serde(rename = "acceptedAudiences")]
    pub accepted_audiences: Vec<String>,
}

/// Configuration-backed OAuth/OAuth-like adapter. Paths are deliberately
/// limited to simple JSON field paths such as `$.data.user.id`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OAuthProviderProperties {
    pub issuer: String,
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "clientSecret")]
    pub client_secret: String,
    #[serde(rename = "callbackUrl")]
    pub callback_url: String,
    pub authorization: AuthorizationEndpointProperties,
    pub token: TokenEndpointProperties,
    pub identity: IdentityMappingProperties,
}

/// Escape hatch for protocols that cannot be expressed by the bounded
/// configuration model. `adapter` selects a registered Provider SPI; settings
/// are adapter-owned and never visible to `AuthZ`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CustomProviderProperties {
    pub adapter: String,
    pub issuer: String,
    pub settings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionProperties {
    pub issuer: String,
    pub audience: String,
    #[serde(with = "humantime_serde")]
    pub ttl: Duration,
    #[serde(rename = "stateTtl", with = "humantime_serde")]
    pub state_ttl: Duration,
    #[serde(rename = "privateKey")]
    pub private_key: String,
    #[serde(rename = "privateKeyFile")]
    pub private_key_file: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthorizationEndpointProperties {
    pub endpoint: String,
    pub scopes: Vec<String>,
    pub query: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TokenEndpointProperties {
    pub endpoint: String,
    pub method: HttpMethod,
    #[serde(rename = "clientCredentials")]
    pub client_credentials: ClientCredentialPlacement,
    pub headers: BTreeMap<String, String>,
    pub query: BTreeMap<String, String>,
    pub body: BTreeMap<String, String>,
    #[serde(rename = "accessToken")]
    pub access_token: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    #[default]
    Post,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientCredentialPlacement {
    #[default]
    Body,
    Query,
    Basic,
    None,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityMappingProperties {
    pub endpoint: Option<String>,
    pub subject: String,
    #[serde(rename = "fallbackSubject")]
    pub fallback_subject: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "trustedClaims")]
    pub trusted_claims: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccountLinkingProperties {
    pub strategy: LinkingStrategy,
    #[serde(rename = "authoritativeProviders")]
    pub authoritative_providers: BTreeSet<String>,
    #[serde(rename = "allowLink")]
    pub allow_link: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinkingStrategy {
    #[default]
    Explicit,
    FirstLogin,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthzProperties {
    pub identity: IdentityProperties,
    pub scope_delivery: ScopeDeliveryProperties,
    pub principal_discovery: PrincipalDiscoveryProperties,
    pub resign: ResignProperties,
    pub api_token: String,
}

/// Re-signing of the short-lived JWT delivered to business microservices.
///
/// On every allowed check Authguard re-signs the verified identity as a JWT
/// carrying `authguardOrigin: true` and replaces the original identity
/// provider (`IdP`) token on the forwarded request. All attributes of the
/// client JWT are preserved — only the marker claim is added — so a
/// microservice verifying this signature proves the request passed through
/// Envoy Gateway and rejects clients that call its API directly. Authguard
/// holds the RSA private key; workloads only hold the paired public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResignProperties {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub max_ttl: Duration,
    /// Base64-encoded PKCS#8 PEM RSA private key injected by the secret provider.
    pub private_key_b64: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrincipalDiscoveryProperties {
    pub keycloak: Vec<KeycloakPrincipalDiscoveryProperties>,
    pub ldap: Vec<LdapPrincipalDiscoveryProperties>,
    pub custom: Vec<CustomPrincipalDiscoveryProperties>,
    pub scim: ScimPrincipalDiscoveryProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeycloakPrincipalDiscoveryProperties {
    pub enabled: bool,
    pub discovery_id: String,
    pub base_url: String,
    pub issuer: String,
    pub realm: String,
    /// Service-account OIDC client-credentials used to obtain the Admin REST
    /// API bearer token.
    pub auth: OidcClientCredentialsProperties,
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
    pub max_page_size: u32,
    pub allow_insecure_http: bool,
}

/// OIDC client-credentials authentication for a service account (SA).
///
/// Connectors speaking OIDC-protected APIs such as Keycloak Admin REST
/// exchange these credentials for an access token — they never log in as a
/// user. The SA lives inside the target realm with the minimal roles it
/// needs (e.g. `realm-management` on Keycloak), never a master admin. LDAP
/// connectors bind directly and use [`LdapBindAuthProperties`] instead.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OidcClientCredentialsProperties {
    /// Overrides the token endpoint derived from the connector URL; useful
    /// when the identity provider is fronted by a gateway with a different
    /// external URL.
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub client_secret_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LdapPrincipalDiscoveryProperties {
    pub enabled: bool,
    pub discovery_id: String,
    pub url: String,
    pub issuer: String,
    pub base_dn: String,
    /// Simple-bind service-account credentials: LDAP authenticates by binding
    /// directly on every connection — no token exchange like the OIDC
    /// connectors.
    pub auth: LdapBindAuthProperties,
    pub user: LdapObjectMappingProperties,
    pub group: LdapObjectMappingProperties,
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
    pub max_page_size: u32,
    pub allow_insecure: bool,
}

/// LDAP simple-bind service-account credentials.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LdapBindAuthProperties {
    pub bind_dn: String,
    pub bind_password: String,
    pub bind_password_file: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LdapObjectMappingProperties {
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
pub struct CustomPrincipalDiscoveryProperties {
    pub enabled: bool,
    pub discovery_id: String,
    pub url: String,
    pub issuer: String,
    pub jwt_token: String,
    pub jwt_token_file: String,
    pub request: CustomRequestBindingProperties,
    pub response: CustomResponseMappingProperties,
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
    pub max_page_size: u32,
    pub allow_insecure_http: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CustomRequestBindingProperties {
    pub path: String,
    pub text_param: String,
    pub offset_param: String,
    pub limit_param: String,
    pub external_id_param: String,
    pub body_template: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CustomResponseMappingProperties {
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
pub struct ScimPrincipalDiscoveryProperties {
    pub enabled: bool,
    pub discovery_id: String,
    pub issuer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScopeDeliveryProperties {
    pub direct_urn_limit: usize,
    pub max_direct_header_bytes: usize,
    #[serde(with = "humantime_serde")]
    pub context_ttl: Duration,
    #[serde(with = "humantime_serde")]
    pub scope_token_ttl: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityProperties {
    pub token_header: String,
    pub principal_id_claim: String,
    pub principal_kind_claim: String,
    pub groups_claim: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConfigPathSegment {
    Key(String),
    Index(usize),
}

/// Process-wide configuration facade.
///
/// Startup installs one immutable snapshot. Refresh atomically replaces the
/// snapshot; consumers obtain a cheap [`Arc`] through [`AppConfig::get`]
/// instead of threading configuration through every service and repository.
pub struct AppConfig;

static APP_CONFIG: OnceLock<RwLock<Arc<AppConfigProperties>>> = OnceLock::new();

impl Default for ServerProperties {
    fn default() -> Self {
        Self {
            service_name: "authguard-authz".to_string(),
            host: IpAddr::from([0, 0, 0, 0]),
            port: 8080,
            scope_port: 8081,
            shutdown_timeout: Duration::from_secs(15),
            request: RequestProperties::default(),
            response: ResponseProperties::default(),
            performance: PerformanceProperties::default(),
        }
    }
}

impl Default for RequestProperties {
    fn default() -> Self {
        Self { max_message_bytes: 1024 * 1024, timeout: Duration::from_secs(5) }
    }
}

impl Default for ResponseProperties {
    fn default() -> Self {
        Self { max_message_bytes: 1024 * 1024 }
    }
}

impl Default for PerformanceProperties {
    fn default() -> Self {
        Self { worker_threads: 2, max_in_flight_requests: 4096 }
    }
}

impl Default for ManagementProperties {
    fn default() -> Self {
        Self {
            enabled: true,
            host: IpAddr::from([0, 0, 0, 0]),
            port: 9091,
            context_path: "/".to_string(),
            health: HealthProperties::default(),
            metrics: MetricsProperties::default(),
            otel: OtelProperties::default(),
        }
    }
}

impl Default for HealthProperties {
    fn default() -> Self {
        Self { liveness_path: "/healthz".to_string(), readiness_path: "/readyz".to_string() }
    }
}

impl Default for MetricsProperties {
    fn default() -> Self {
        Self { enabled: true, path: "/metrics".to_string() }
    }
}

impl Default for OtelProperties {
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

impl Default for LoggingProperties {
    fn default() -> Self {
        Self { mode: "JSON".to_string(), level: "info,tower_http=info".to_string() }
    }
}

impl Default for CacheProperties {
    fn default() -> Self {
        Self {
            provider: "Memory".to_string(),
            memory: MemoryCacheProperties::default(),
            redis: RedisClusterProperties::default(),
        }
    }
}

impl Default for MemoryCacheProperties {
    fn default() -> Self {
        Self {
            initial_capacity: 32,
            max_capacity: 65_535,
            ttl: Duration::from_secs(60 * 60),
            eviction_policy: "LRU".to_string(),
        }
    }
}

impl Default for RedisClusterProperties {
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

impl Default for StorageProperties {
    fn default() -> Self {
        Self {
            provider: "SQLite".to_string(),
            bootstrap_policy: None,
            sqlite: SqliteProperties::default(),
            postgres: PostgresProperties::default(),
        }
    }
}

impl Default for SqliteProperties {
    fn default() -> Self {
        Self {
            url: "sqlite://authguard.db?mode=rwc".to_string(),
            max_connections: 1,
            connect_timeout: Duration::from_secs(5),
        }
    }
}

impl Default for PostgresProperties {
    fn default() -> Self {
        Self {
            url: String::new(),
            username: String::new(),
            password: String::new(),
            max_connections: 20,
            min_connections: 0,
            connect_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(600),
            validate_on_acquire: true,
        }
    }
}

impl Default for OidcProviderProperties {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            callback_url: String::new(),
            scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
            userinfo: true,
            token_introspection: None,
            identity: IdentityMappingProperties {
                subject: "$.sub".to_string(),
                username: Some("$.preferred_username".to_string()),
                email: Some("$.email".to_string()),
                ..IdentityMappingProperties::default()
            },
        }
    }
}

impl Default for SessionProperties {
    fn default() -> Self {
        Self {
            issuer: "authguard-authn".to_string(),
            audience: "authguard".to_string(),
            ttl: Duration::from_secs(300),
            state_ttl: Duration::from_secs(300),
            private_key: String::new(),
            private_key_file: String::new(),
        }
    }
}

impl Default for TokenEndpointProperties {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            method: HttpMethod::Post,
            client_credentials: ClientCredentialPlacement::Body,
            headers: BTreeMap::new(),
            query: BTreeMap::new(),
            body: BTreeMap::new(),
            access_token: "$.access_token".to_string(),
        }
    }
}

impl Default for AccountLinkingProperties {
    fn default() -> Self {
        Self {
            strategy: LinkingStrategy::Explicit,
            authoritative_providers: BTreeSet::new(),
            allow_link: BTreeMap::new(),
        }
    }
}

impl Default for ResignProperties {
    fn default() -> Self {
        Self { enabled: false, max_ttl: Duration::from_secs(60), private_key_b64: String::new() }
    }
}

impl Default for KeycloakPrincipalDiscoveryProperties {
    fn default() -> Self {
        Self {
            enabled: false,
            discovery_id: String::new(),
            base_url: String::new(),
            issuer: String::new(),
            realm: String::new(),
            auth: OidcClientCredentialsProperties::default(),
            connect_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(5),
            max_page_size: 100,
            allow_insecure_http: false,
        }
    }
}

impl Default for LdapPrincipalDiscoveryProperties {
    fn default() -> Self {
        Self {
            enabled: false,
            discovery_id: String::new(),
            url: String::new(),
            issuer: String::new(),
            base_dn: String::new(),
            auth: LdapBindAuthProperties::default(),
            user: LdapObjectMappingProperties::default(),
            group: LdapObjectMappingProperties::default(),
            connect_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(5),
            max_page_size: 100,
            allow_insecure: false,
        }
    }
}

impl Default for CustomPrincipalDiscoveryProperties {
    fn default() -> Self {
        Self {
            enabled: false,
            discovery_id: String::new(),
            url: String::new(),
            issuer: String::new(),
            jwt_token: String::new(),
            jwt_token_file: String::new(),
            request: CustomRequestBindingProperties::default(),
            response: CustomResponseMappingProperties::default(),
            connect_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(5),
            max_page_size: 100,
            allow_insecure_http: false,
        }
    }
}

impl Default for CustomRequestBindingProperties {
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

impl Default for CustomResponseMappingProperties {
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

impl Default for ScimPrincipalDiscoveryProperties {
    fn default() -> Self {
        Self {
            enabled: false,
            discovery_id: "corporate-scim".to_string(),
            issuer: "https://idp.example.com/scim/example-corp".to_string(),
        }
    }
}

impl Default for ScopeDeliveryProperties {
    fn default() -> Self {
        Self {
            direct_urn_limit: 32,
            max_direct_header_bytes: 8 * 1024,
            context_ttl: Duration::from_secs(30),
            scope_token_ttl: Duration::from_secs(30),
        }
    }
}

impl Default for IdentityProperties {
    fn default() -> Self {
        Self {
            token_header: "x-authguard-id-token".to_string(),
            principal_id_claim: "principal_id".to_string(),
            principal_kind_claim: "principal_kind".to_string(),
            groups_claim: "authguard_group_ids".to_string(),
        }
    }
}

impl ProviderProperties {
    #[must_use]
    pub const fn oauth(&self) -> Option<&OAuthProviderProperties> {
        match self {
            Self::OAuth2(config) | Self::OAuth2Like(config) => Some(config),
            Self::Oidc(_) | Self::Custom(_) => None,
        }
    }
}

impl AppConfigProperties {
    #[must_use]
    pub fn get_server(&self) -> &ServerProperties {
        &self.server
    }

    #[must_use]
    pub fn get_mgmt(&self) -> &ManagementProperties {
        &self.mgmt
    }

    #[must_use]
    pub fn get_logging(&self) -> &LoggingProperties {
        &self.logging
    }

    #[must_use]
    pub fn get_cache(&self) -> &CacheProperties {
        &self.cache
    }

    #[must_use]
    pub fn get_storage(&self) -> &StorageProperties {
        &self.storage
    }

    #[must_use]
    pub fn get_authn(&self) -> &AuthnProperties {
        &self.authn
    }

    #[must_use]
    pub fn get_authz(&self) -> &AuthzProperties {
        &self.authz
    }

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

impl AppConfig {
    #[must_use]
    pub fn get() -> Arc<AppConfigProperties> {
        APP_CONFIG
            .get_or_init(|| RwLock::new(Arc::new(AppConfigProperties::default())))
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Loads the `AuthZ` view of the shared product YAML and installs it.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration or deployment constraints.
    pub fn load() -> anyhow::Result<Arc<AppConfigProperties>> {
        Self::install(AppConfigProperties::load()?)
    }

    /// Loads the `AuthN` view without resolving or validating `AuthZ`-only secrets.
    ///
    /// # Errors
    ///
    /// Returns an error for unreadable or invalid shared configuration.
    pub fn load_authn(path: impl AsRef<Path>) -> anyhow::Result<Arc<AppConfigProperties>> {
        Self::install(AppConfigProperties::load_for_authn(path.as_ref())?)
    }

    /// Reloads and atomically replaces the `AuthZ` configuration snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration or deployment constraints.
    pub fn refresh() -> anyhow::Result<Arc<AppConfigProperties>> {
        Self::load()
    }

    fn install(config: AppConfigProperties) -> anyhow::Result<Arc<AppConfigProperties>> {
        let config = Arc::new(config);
        *APP_CONFIG
            .get_or_init(|| RwLock::new(config.clone()))
            .write()
            .map_err(|_| anyhow::anyhow!("AppConfig write lock poisoned"))? = config.clone();
        Ok(config)
    }
}

impl AppConfigProperties {
    /// Validates limits and paths before listeners or exporters are started.
    ///
    /// # Errors
    ///
    /// Returns a descriptive error for invalid or unsafe limits.
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_server(&self.server)?;
        validate_management(&self.mgmt)?;
        validate_scope_delivery(&self.authz.scope_delivery)?;
        validate_identity(&self.authz.identity)?;
        validate_principal_discovery(&self.authz.principal_discovery)?;
        validate_resign(&self.authz.resign)?;
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

fn validate_server(server: &ServerProperties) -> anyhow::Result<()> {
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

fn validate_management(mgmt: &ManagementProperties) -> anyhow::Result<()> {
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

fn validate_scope_delivery(delivery: &ScopeDeliveryProperties) -> anyhow::Result<()> {
    if delivery.direct_urn_limit == 0 {
        bail!("authz.scope_delivery.direct_urn_limit must be positive");
    }
    if !(1024..=64 * 1024).contains(&delivery.max_direct_header_bytes) {
        bail!("authz.scope_delivery.max_direct_header_bytes must be between 1 KiB and 64 KiB");
    }
    if delivery.context_ttl.is_zero() || delivery.scope_token_ttl.is_zero() {
        bail!("authz.scope_delivery TTLs must be positive");
    }
    Ok(())
}

fn validate_identity(identity: &IdentityProperties) -> anyhow::Result<()> {
    if identity.token_header.trim().is_empty()
        || identity.principal_id_claim.trim().is_empty()
        || identity.principal_kind_claim.trim().is_empty()
        || identity.groups_claim.trim().is_empty()
    {
        bail!("authz.identity token header and claim names must not be empty");
    }
    Ok(())
}

fn validate_principal_discovery(config: &PrincipalDiscoveryProperties) -> anyhow::Result<()> {
    let keycloak: Vec<_> = config.keycloak.iter().filter(|entry| entry.enabled).collect();
    let ldap: Vec<_> = config.ldap.iter().filter(|entry| entry.enabled).collect();
    let custom: Vec<_> = config.custom.iter().filter(|entry| entry.enabled).collect();
    validate_unique_protocol(keycloak.len(), "FED_KEYCLOAK")?;
    validate_unique_protocol(ldap.len(), "FED_LDAP")?;
    validate_unique_protocol(custom.len(), "FED_CUSTOM")?;
    for keycloak in keycloak {
        validate_keycloak(keycloak)?;
    }
    for ldap in ldap {
        validate_ldap(ldap)?;
    }
    for custom in custom {
        validate_http_discovery(custom)?;
    }
    validate_scim(&config.scim)
}

/// Each protocol runs at most one active connector: search candidates carry
/// their source `(provider_id, issuer)`, and dispatch by protocol must resolve
/// to exactly one source.
fn validate_unique_protocol(active_entries: usize, protocol: &str) -> anyhow::Result<()> {
    if active_entries > 1 {
        bail!("at most one enabled `{protocol}` principal discovery entry is allowed");
    }
    Ok(())
}

fn validate_keycloak(keycloak: &KeycloakPrincipalDiscoveryProperties) -> anyhow::Result<()> {
    if keycloak.discovery_id.trim().is_empty()
        || keycloak.base_url.trim().is_empty()
        || keycloak.realm.trim().is_empty()
    {
        bail!("each Keycloak principal discovery requires id, URL and realm");
    }
    validate_client_credentials("keycloak.auth", &keycloak.auth)?;
    if keycloak.connect_timeout.is_zero()
        || keycloak.request_timeout.is_zero()
        || keycloak.max_page_size == 0
    {
        bail!("Keycloak principal discovery timeouts and max_page_size must be positive");
    }
    Ok(())
}

fn validate_ldap(ldap: &LdapPrincipalDiscoveryProperties) -> anyhow::Result<()> {
    if ldap.discovery_id.trim().is_empty()
        || ldap.url.trim().is_empty()
        || ldap.issuer.trim().is_empty()
        || ldap.base_dn.trim().is_empty()
        || ldap.auth.bind_dn.trim().is_empty()
        || (ldap.auth.bind_password.is_empty() == ldap.auth.bind_password_file.is_empty())
    {
        bail!(
            "each LDAP principal discovery requires id, URL, issuer, base DN and exactly one of auth.bind_password or auth.bind_password_file"
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

fn validate_http_discovery(discovery: &CustomPrincipalDiscoveryProperties) -> anyhow::Result<()> {
    if discovery.discovery_id.trim().is_empty()
        || discovery.url.trim().is_empty()
        || discovery.issuer.trim().is_empty()
        || (discovery.jwt_token.is_empty() == discovery.jwt_token_file.is_empty())
    {
        bail!(
            "each HTTP principal discovery requires id, URL, issuer and exactly one of jwt_token or jwt_token_file"
        );
    }
    if discovery.request.path.trim().is_empty()
        || discovery.request.text_param.trim().is_empty()
        || discovery.request.offset_param.trim().is_empty()
        || discovery.request.limit_param.trim().is_empty()
        || discovery.request.external_id_param.trim().is_empty()
        || discovery.response.id_attr.trim().is_empty()
        || discovery.response.display_name_attr.trim().is_empty()
    {
        bail!(
            "HTTP principal discovery requires request path, query parameter names and response id/display-name attributes"
        );
    }
    if discovery.connect_timeout.is_zero()
        || discovery.request_timeout.is_zero()
        || discovery.max_page_size == 0
    {
        bail!("HTTP principal discovery timeouts and max_page_size must be positive");
    }
    Ok(())
}

/// Validates an OIDC client-credentials block: a client id plus exactly one
/// of the secret sources. A custom
/// `token_url` must be an http(s) endpoint.
fn validate_client_credentials(
    path: &str,
    auth: &OidcClientCredentialsProperties,
) -> anyhow::Result<()> {
    if auth.client_id.trim().is_empty()
        || (auth.client_secret.is_empty() == auth.client_secret_file.is_empty())
    {
        bail!("{path} requires client_id and exactly one of client_secret or client_secret_file");
    }
    if !auth.token_url.is_empty() && !auth.token_url.starts_with("http") {
        bail!("{path}.token_url must be an http(s) endpoint");
    }
    Ok(())
}

fn validate_resign(resign: &ResignProperties) -> anyhow::Result<()> {
    if !resign.enabled {
        return Ok(());
    }
    if resign.max_ttl.is_zero() {
        bail!("authz.resign.max_ttl must be positive when enabled");
    }
    if resign.private_key_b64.trim().is_empty() {
        bail!("authz.resign.private_key_b64 is required when enabled");
    }
    Ok(())
}

fn validate_scim(scim: &ScimPrincipalDiscoveryProperties) -> anyhow::Result<()> {
    if scim.enabled && (scim.discovery_id.trim().is_empty() || scim.issuer.trim().is_empty()) {
        bail!("authz.principal_discovery.scim requires discovery_id and issuer");
    }
    Ok(())
}

fn validate_storage(storage: &StorageProperties) -> anyhow::Result<()> {
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
        "postgres" if storage.postgres.min_connections > storage.postgres.max_connections => {
            bail!("storage.postgres.min_connections must not exceed max_connections");
        }
        "postgres" if storage.postgres.connect_timeout.is_zero() => {
            bail!("storage.postgres.connect_timeout must be positive");
        }
        "postgres" if storage.postgres.idle_timeout.is_zero() => {
            bail!("storage.postgres.idle_timeout must be positive");
        }
        "sqlite" | "postgres" => {}
        provider => bail!("storage.provider must be SQLite or postgres, got `{provider}`"),
    }
    Ok(())
}

fn validate_cache(cache: &CacheProperties) -> anyhow::Result<()> {
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

fn validate_redis_cache(redis: &RedisClusterProperties) -> anyhow::Result<()> {
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

fn merged_yaml(
    default_yaml: Option<&'static str>,
    file: Option<&Path>,
) -> anyhow::Result<serde_yaml::Value> {
    let mut builder = Config::builder();
    if let Some(default_yaml) = default_yaml {
        builder = builder.add_source(File::from_str(default_yaml, FileFormat::Yaml));
    }
    if let Some(file) = file {
        builder = builder.add_source(File::from(file).required(true));
    }
    let mut value = builder
        .build()
        .context("merge AuthGuard defaults and YAML")?
        .try_deserialize::<serde_yaml::Value>()
        .context("materialize AuthGuard YAML")?;
    apply_environment_overrides(&mut value)?;
    Ok(value)
}

fn apply_environment_overrides(root: &mut serde_yaml::Value) -> anyhow::Result<()> {
    apply_environment_entries(root, std::env::vars())
}

fn apply_environment_entries(
    root: &mut serde_yaml::Value,
    entries: impl IntoIterator<Item = (String, String)>,
) -> anyhow::Result<()> {
    for (name, raw_value) in entries.into_iter().filter(|(name, _)| name.starts_with(ENV_PREFIX)) {
        let path = parse_environment_path(&name[ENV_PREFIX.len()..])
            .with_context(|| format!("parse environment override {name}"))?;
        let value = serde_yaml::from_str::<serde_yaml::Value>(&raw_value)
            .unwrap_or(serde_yaml::Value::String(raw_value));
        set_yaml_path(root, &path, value)
            .with_context(|| format!("apply environment override {name}"))?;
    }
    Ok(())
}

fn parse_environment_path(path: &str) -> anyhow::Result<Vec<ConfigPathSegment>> {
    let mut parsed = Vec::new();
    for segment in path.split("__").filter(|segment| !segment.is_empty()) {
        let mut remaining = segment;
        if !remaining.starts_with('[') {
            let key_end = remaining.find('[').unwrap_or(remaining.len());
            parsed.push(ConfigPathSegment::Key(remaining[..key_end].to_string()));
            remaining = &remaining[key_end..];
        }
        while !remaining.is_empty() {
            if !remaining.starts_with('[') {
                bail!("invalid array path segment `{segment}`");
            }
            let index_end = remaining
                .find(']')
                .with_context(|| format!("unclosed array index in `{segment}`"))?;
            let index = remaining[1..index_end]
                .parse::<usize>()
                .with_context(|| format!("invalid array index in `{segment}`"))?;
            parsed.push(ConfigPathSegment::Index(index));
            remaining = &remaining[index_end + 1..];
        }
    }
    if parsed.is_empty() {
        bail!("configuration path is empty");
    }
    Ok(parsed)
}

fn set_yaml_path(
    current: &mut serde_yaml::Value,
    path: &[ConfigPathSegment],
    value: serde_yaml::Value,
) -> anyhow::Result<()> {
    let Some((segment, remaining)) = path.split_first() else {
        *current = value;
        return Ok(());
    };
    match segment {
        ConfigPathSegment::Index(index) => {
            if !current.is_sequence() {
                *current = serde_yaml::Value::Sequence(Vec::new());
            }
            let items = current.as_sequence_mut().expect("sequence initialized above");
            while items.len() <= *index {
                items.push(serde_yaml::Value::Null);
            }
            set_yaml_path(&mut items[*index], remaining, value)
        }
        ConfigPathSegment::Key(segment) => {
            if !current.is_mapping() {
                *current = serde_yaml::Value::Mapping(serde_yaml::Mapping::default());
            }
            let mapping = current.as_mapping_mut().expect("mapping initialized above");
            let normalized = normalized_property_name(segment);
            let key = mapping
                .keys()
                .find(|key| {
                    key.as_str().is_some_and(|key| normalized_property_name(key) == normalized)
                })
                .cloned()
                .unwrap_or_else(|| serde_yaml::Value::String(segment.to_ascii_lowercase()));
            if remaining.is_empty() {
                mapping.insert(key, value);
                return Ok(());
            }
            let child = mapping.entry(key).or_insert(serde_yaml::Value::Null);
            set_yaml_path(child, remaining, value)
        }
    }
}

fn normalized_property_name(value: &str) -> String {
    value.chars().filter(char::is_ascii_alphanumeric).flat_map(char::to_lowercase).collect()
}

/// Reads an optional newline-delimited `KEY=VALUE` secret projection.
///
/// # Errors
///
/// Returns an error when the configured file cannot be read.
pub fn read_secret_env_file(path: Option<&str>) -> anyhow::Result<HashMap<String, String>> {
    let mut values = HashMap::new();
    if let Some(path) = path {
        let content = std::fs::read_to_string(Path::new(path))?;
        for line in content.lines() {
            let Some((key, value)) = line.split_once('=') else { continue };
            values.insert(key.trim().to_string(), value.trim_end().to_string());
        }
    }
    Ok(values)
}

#[must_use]
pub fn secret_env(name: &str) -> Option<String> {
    read_secret_env_file(std::env::var(SECRET_ENV_FILE_ENV).ok().as_deref())
        .ok()
        .and_then(|values| values.get(name).cloned())
        .or_else(|| std::env::var(name).ok())
}

fn expand_authz_owned_env_refs(
    value: &mut serde_yaml::Value,
    env_values: &HashMap<String, String>,
) -> anyhow::Result<()> {
    let mapping =
        value.as_mapping_mut().context("AuthGuard configuration root must be a YAML mapping")?;
    for (key, value) in mapping {
        if key.as_str() != Some("authn") {
            expand_yaml_env_refs(value, env_values)?;
        }
    }
    Ok(())
}

fn expand_authn_owned_env_refs(
    value: &mut serde_yaml::Value,
    env_values: &HashMap<String, String>,
) -> anyhow::Result<()> {
    let mapping =
        value.as_mapping_mut().context("AuthGuard configuration root must be a YAML mapping")?;
    for (key, value) in mapping {
        if key.as_str() != Some("authz") {
            expand_yaml_env_refs(value, env_values)?;
        }
    }
    Ok(())
}

fn expand_yaml_env_refs(
    value: &mut serde_yaml::Value,
    env_values: &HashMap<String, String>,
) -> anyhow::Result<()> {
    match value {
        serde_yaml::Value::Mapping(values) => {
            for value in values.values_mut() {
                expand_yaml_env_refs(value, env_values)?;
            }
        }
        serde_yaml::Value::Sequence(values) => {
            for value in values {
                expand_yaml_env_refs(value, env_values)?;
            }
        }
        serde_yaml::Value::String(text) if text.starts_with("${") && text.ends_with('}') => {
            let key = &text[2..text.len() - 1];
            if matches!(key, "clientId" | "clientSecret" | "authorizationCode" | "redirectUri") {
                return Ok(());
            }
            *text =
                env_values.get(key).cloned().or_else(|| std::env::var(key).ok()).with_context(
                    || format!("configuration references missing environment {key}"),
                )?;
        }
        _ => {}
    }
    Ok(())
}

fn runtime_replica_count() -> anyhow::Result<usize> {
    std::env::var("AUTHGUARD_REPLICA_COUNT").map_or(Ok(1), |value| {
        value.parse::<usize>().context("AUTHGUARD_REPLICA_COUNT must be a positive integer")
    })
}

impl AppConfigProperties {
    /// Loads defaults, the optional shared YAML, then arbitrary nested environment overrides.
    ///
    /// # Errors
    ///
    /// Returns an error for unreadable, invalid, or unresolved configuration.
    pub fn load() -> anyhow::Result<Self> {
        let configured_path =
            std::env::var(CONFIG_FILE_ENV).unwrap_or_else(|_| DEFAULT_CONFIG.to_string());
        let configured_path = Path::new(&configured_path);
        let file = configured_path.exists().then_some(configured_path);
        let mut value = merged_yaml(Some(DEFAULT_CONFIG_YAML), file)?;
        let env_values = read_secret_env_file(std::env::var(SECRET_ENV_FILE_ENV).ok().as_deref())?;
        expand_authz_owned_env_refs(&mut value, &env_values)?;
        let config: Self =
            serde_yaml::from_value(value).context("decode AuthGuard configuration")?;
        config.validate()?;
        config.validate_deployment(runtime_replica_count()?)?;
        Ok(config)
    }

    fn load_for_authn(path: &Path) -> anyhow::Result<Self> {
        let mut value = merged_yaml(Some(DEFAULT_CONFIG_YAML), Some(path))?;
        let env_values = read_secret_env_file(std::env::var(SECRET_ENV_FILE_ENV).ok().as_deref())?;
        expand_authn_owned_env_refs(&mut value, &env_values)?;
        let config: Self = serde_yaml::from_value(value)
            .with_context(|| format!("decode AuthN configuration {}", path.display()))?;
        validate_storage(&config.storage)?;
        Ok(config)
    }

    /// Loads and validates one explicit YAML without process-environment overrides.
    ///
    /// # Errors
    ///
    /// Returns an error when the YAML cannot be read, decoded, or validated.
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let config = Config::builder()
            .add_source(File::from(path.as_ref()).required(true))
            .build()?
            .try_deserialize::<Self>()?;
        config.validate()?;
        Ok(config)
    }

    #[cfg(test)]
    fn from_default_yaml() -> anyhow::Result<Self> {
        Config::builder()
            .add_source(File::from_str(DEFAULT_CONFIG_YAML, FileFormat::Yaml))
            .build()?
            .try_deserialize::<Self>()
            .context("decode default AuthGuard configuration")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvCleanup(Vec<&'static str>);

    impl Drop for EnvCleanup {
        fn drop(&mut self) {
            for name in &self.0 {
                std::env::remove_var(name);
            }
        }
    }

    fn apply_overrides(yaml: &str, entries: &[(&str, &str)]) -> serde_yaml::Value {
        let mut value = serde_yaml::from_str(yaml).expect("test YAML");
        apply_environment_entries(
            &mut value,
            entries.iter().map(|(name, value)| ((*name).to_string(), (*value).to_string())),
        )
        .expect("environment overrides");
        value
    }

    #[test]
    fn environment_overrides_scalar_types_and_relaxed_names() {
        let value = apply_overrides(
            "server: {service_name: yaml, port: 8080}\nmgmt: {otel: {enabled: false}}\n",
            &[
                ("AUTHGUARD__SERVER__SERVICE_NAME", "env-service"),
                ("AUTHGUARD__SERVER__PORT", "8180"),
                ("AUTHGUARD__MGMT__OTEL__ENABLED", "true"),
            ],
        );
        assert_eq!(value["server"]["service_name"], "env-service");
        assert_eq!(value["server"]["port"], 8180);
        assert_eq!(value["mgmt"]["otel"]["enabled"], true);
    }

    #[test]
    fn environment_overrides_scalar_array_elements() {
        let value = apply_overrides(
            "cache: {redis: {nodes: [redis-0:6379, redis-1:6379]}}\n",
            &[("AUTHGUARD__CACHE__REDIS__NODES[1]", "redis-2:6379")],
        );
        assert_eq!(value["cache"]["redis"]["nodes"][1], "redis-2:6379");
    }

    #[test]
    fn environment_overrides_objects_inside_arrays() {
        let value = apply_overrides(
            "authz: {principal_discovery: {keycloak: [{enabled: false}, {enabled: false}]}}\n",
            &[("AUTHGUARD__AUTHZ__PRINCIPAL_DISCOVERY__KEYCLOAK[1]__ENABLED", "true")],
        );
        assert_eq!(value["authz"]["principal_discovery"]["keycloak"][1]["enabled"], true);
    }

    #[test]
    fn environment_supports_bracket_indices_on_arbitrary_nested_shapes() {
        let value = apply_overrides(
            "authn: {principal_discovery: [{keycloak: {enable: false}}, {keycloak: {enable: false}}]}\n",
            &[(
                "AUTHGUARD__AUTHN__PRINCIPAL_DISCOVERY[1]__KEYCLOAK__ENABLE",
                "true",
            )],
        );
        assert_eq!(value["authn"]["principal_discovery"][1]["keycloak"]["enable"], true);
    }

    #[test]
    fn environment_overrides_dynamic_provider_maps() {
        let value = apply_overrides(
            "authn: {providers: {github: {identity: {subject: '$.id'}}}}\n",
            &[("AUTHGUARD__AUTHN__PROVIDERS__GITHUB__IDENTITY__SUBJECT", "$.node_id")],
        );
        assert_eq!(value["authn"]["providers"]["github"]["identity"]["subject"], "$.node_id");
    }

    #[test]
    fn environment_creates_nested_map_and_array_values() {
        let value = apply_overrides(
            "authn: {accountLinking: {allowLink: {}}}\n",
            &[("AUTHGUARD__AUTHN__ACCOUNT_LINKING__ALLOW_LINK__CORPORATE_DSP[0]", "github")],
        );
        assert_eq!(value["authn"]["accountLinking"]["allowLink"]["corporate_dsp"][0], "github");
    }

    #[test]
    fn provider_runtime_templates_are_not_treated_as_secret_environment_refs() {
        let mut value = serde_yaml::from_str(
            "authn: {providers: {wechat: {token: {query: {appid: '${clientId}', secret: '${clientSecret}', code: '${authorizationCode}', redirect: '${redirectUri}'}}}}}\n",
        )
        .expect("provider YAML");
        expand_authn_owned_env_refs(&mut value, &HashMap::new()).expect("runtime templates");
        let query = &value["authn"]["providers"]["wechat"]["token"]["query"];
        assert_eq!(query["appid"], "${clientId}");
        assert_eq!(query["secret"], "${clientSecret}");
        assert_eq!(query["code"], "${authorizationCode}");
        assert_eq!(query["redirect"], "${redirectUri}");
    }

    #[test]
    fn environment_rejects_malformed_array_indices() {
        let mut value = serde_yaml::from_str("authn: {}\n").expect("test YAML");
        let error = apply_environment_entries(
            &mut value,
            [("AUTHGUARD__AUTHN__PROVIDERS[one]".to_string(), "github".to_string())],
        )
        .expect_err("invalid index must fail");
        assert!(error.to_string().contains("parse environment override"));
    }

    #[test]
    fn arbitrary_nested_environment_values_override_yaml() {
        let _guard = ENV_LOCK.lock().unwrap();
        let cleanup = EnvCleanup(vec![
            "AUTHGUARD__AUTHN__SESSION__AUDIENCE",
            "AUTHGUARD__AUTHN__SESSION__STATE_TTL",
            "AUTHGUARD__STORAGE__POSTGRES__MAX_CONNECTIONS",
            "AUTHGUARD__MGMT__OTEL__ENABLED",
        ]);
        let directory =
            std::env::temp_dir().join(format!("authguard-config-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let file = directory.join("authguard.yaml");
        std::fs::write(
            &file,
            r"
authn:
  session:
    audience: yaml-audience
    stateTtl: 1m
storage:
  provider: SQLite
  postgres:
    max_connections: 2
logging: {}
mgmt:
  metrics: {}
  otel:
    enabled: false
",
        )
        .unwrap();
        std::env::set_var("AUTHGUARD__AUTHN__SESSION__AUDIENCE", "env-audience");
        std::env::set_var("AUTHGUARD__AUTHN__SESSION__STATE_TTL", "3m");
        std::env::set_var("AUTHGUARD__STORAGE__POSTGRES__MAX_CONNECTIONS", "17");
        std::env::set_var("AUTHGUARD__MGMT__OTEL__ENABLED", "true");

        let config = AppConfigProperties::load_for_authn(&file).unwrap();
        std::fs::remove_dir_all(&directory).ok();
        drop(cleanup);

        assert_eq!(config.authn.session.audience, "env-audience");
        assert_eq!(config.authn.session.state_ttl, Duration::from_secs(180));
        assert_eq!(config.storage.postgres.max_connections, 17);
        assert!(config.mgmt.otel.enabled);
    }

    #[test]
    fn each_service_resolves_only_its_owned_secret_subtree() {
        let mut authorization_view = serde_yaml::from_str::<serde_yaml::Value>(
            r"
authn:
  session:
    privateKey: ${AUTHN_ONLY_KEY}
authz:
  api_token: resolved-authz-secret
",
        )
        .unwrap();
        expand_authz_owned_env_refs(&mut authorization_view, &HashMap::new()).unwrap();
        assert_eq!(
            authorization_view["authn"]["session"]["privateKey"].as_str(),
            Some("${AUTHN_ONLY_KEY}")
        );

        let mut authentication_view = serde_yaml::from_str::<serde_yaml::Value>(
            r"
authn:
  providers: {}
authz:
  api_token: ${AUTHZ_ONLY_SECRET}
storage: {}
logging: {}
mgmt: {}
",
        )
        .unwrap();
        expand_authn_owned_env_refs(&mut authentication_view, &HashMap::new()).unwrap();
        assert_eq!(
            authentication_view["authz"]["api_token"].as_str(),
            Some("${AUTHZ_ONLY_SECRET}")
        );
    }

    #[test]
    fn provider_yaml_keeps_protocol_and_linking_policy_separate() {
        let config: AuthnProperties = serde_yaml::from_str(
            r"
providers:
  corporate-oidc:
    type: oidc
    issuer: https://sso.example.com/realms/corporate
    clientId: authguard
    clientSecret: test-only-secret
    callbackUrl: https://app.example.com/auth/v1/providers/corporate-oidc/callback
    scopes: [openid, profile, email]
    userinfo: true
    tokenIntrospection:
      endpoint: https://sso.example.com/realms/corporate/protocol/openid-connect/token/introspect
      acceptedAudiences: [customer-growth-job-service]
    identity:
      subject: $.sub
      username: $.preferred_username
      email: $.email
  github:
    type: oauth2
    issuer: https://github.com
    authorization:
      endpoint: https://github.com/login/oauth/authorize
      scopes: [read:user, user:email]
    token:
      endpoint: https://github.com/login/oauth/access_token
      method: POST
    identity:
      endpoint: https://api.github.com/user
      subject: $.id
      username: $.login
      email: $.email
accountLinking:
  strategy: explicit
  authoritativeProviders: [corporate-dsp]
  allowLink:
    corporate-dsp: [github, wechat]
",
        )
        .expect("provider configuration");

        let ProviderProperties::Oidc(oidc) = &config.providers["corporate-oidc"] else {
            panic!("corporate-oidc must decode as OIDC");
        };
        assert_eq!(
            oidc.token_introspection.as_ref().expect("introspection").accepted_audiences,
            ["customer-growth-job-service"]
        );
        assert!(matches!(config.providers["github"], ProviderProperties::OAuth2(_)));
        assert_eq!(config.account_linking.strategy, LinkingStrategy::Explicit);
        assert!(config.account_linking.allow_link["corporate-dsp"].contains("github"));
    }

    #[test]
    fn provider_cannot_declare_account_governance_role() {
        let error = serde_yaml::from_str::<AuthnProperties>(
            r"
providers:
  github:
    type: oauth2
    role: secondary
",
        )
        .expect_err("provider governance field must be rejected");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn annotated_default_configuration_is_valid() {
        let config = AppConfigProperties::from_default_yaml().expect("decode defaults");
        config.validate().expect("valid");
        assert_eq!(config.server.service_name, "authguard-authz");
        assert_eq!(config.mgmt.port, 9091);
        assert_eq!(config.storage.provider, "SQLite");
        assert_eq!(config.cache.provider, "Memory");
        assert_eq!(config.cache.memory.max_capacity, 65_535);
    }

    #[test]
    fn rejects_unbounded_worker_configuration() {
        let config = AppConfigProperties {
            server: ServerProperties {
                performance: PerformanceProperties {
                    worker_threads: 0,
                    ..PerformanceProperties::default()
                },
                ..ServerProperties::default()
            },
            ..AppConfigProperties::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_removed_file_storage_and_cache_providers() {
        let mut file_storage = AppConfigProperties::default();
        file_storage.storage.provider = "file".to_string();
        assert!(file_storage.validate().is_err());

        let mut file_cache = AppConfigProperties::default();
        file_cache.cache.provider = "File".to_string();
        assert!(file_cache.validate().is_err());
    }

    #[test]
    fn rejects_process_local_providers_in_multi_replica_deployments() {
        let mut memory = AppConfigProperties::default();
        memory.storage.provider = "postgres".to_string();
        assert!(memory.validate_deployment(2).is_err());

        let mut sqlite = AppConfigProperties::default();
        sqlite.cache.provider = "Redis".to_string();
        assert!(sqlite.validate_deployment(2).is_err());

        let mut shared = AppConfigProperties::default();
        shared.storage.provider = "postgres".to_string();
        shared.cache.provider = "Redis".to_string();
        assert!(shared.validate_deployment(2).is_ok());
        assert!(shared.validate_deployment(0).is_err());
    }

    #[test]
    fn rejects_redis_replica_reads_for_scope_tokens() {
        let mut config = AppConfigProperties::default();
        config.cache.provider = "Redis".to_string();
        config.cache.redis.read_from_replica = true;

        assert!(config.validate().is_err());
    }

    #[test]
    fn validates_file_backed_federated_discovery_credentials() {
        let mut config = AppConfigProperties::default();
        config.authz.principal_discovery.keycloak = vec![KeycloakPrincipalDiscoveryProperties {
            enabled: true,
            discovery_id: "corporate-keycloak".to_string(),
            base_url: "https://id.example.com".to_string(),
            issuer: "https://id.example.com/realms/corporate".to_string(),
            realm: "corporate".to_string(),
            auth: OidcClientCredentialsProperties {
                client_id: "authguard-principal-discovery".to_string(),
                client_secret_file: "/run/secrets/keycloak-client-secret".to_string(),
                ..OidcClientCredentialsProperties::default()
            },
            ..KeycloakPrincipalDiscoveryProperties::default()
        }];
        let object_mapping = LdapObjectMappingProperties {
            object_filter: "(objectClass=inetOrgPerson)".to_string(),
            id_attribute: "entryUUID".to_string(),
            name_attribute: "uid".to_string(),
            search_attributes: vec!["uid".to_string(), "mail".to_string()],
            ..LdapObjectMappingProperties::default()
        };
        config.authz.principal_discovery.ldap = vec![LdapPrincipalDiscoveryProperties {
            enabled: true,
            discovery_id: "corporate-ldap".to_string(),
            url: "ldaps://ldap.example.com:636".to_string(),
            issuer: "urn:identity:corporate-ldap".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            auth: LdapBindAuthProperties {
                bind_dn: "cn=authguard,ou=service-accounts,dc=example,dc=com".to_string(),
                bind_password_file: "/run/secrets/ldap-bind-password".to_string(),
                ..LdapBindAuthProperties::default()
            },
            user: object_mapping.clone(),
            group: LdapObjectMappingProperties {
                object_filter: "(objectClass=groupOfNames)".to_string(),
                name_attribute: "cn".to_string(),
                search_attributes: vec!["cn".to_string()],
                ..object_mapping
            },
            ..LdapPrincipalDiscoveryProperties::default()
        }];
        config.authz.principal_discovery.custom = vec![CustomPrincipalDiscoveryProperties {
            enabled: true,
            discovery_id: "dsp-directory".to_string(),
            url: "https://dsp.example.com/identity".to_string(),
            issuer: "https://dsp.example.com".to_string(),
            jwt_token_file: "/run/secrets/dsp-jwt".to_string(),
            ..CustomPrincipalDiscoveryProperties::default()
        }];

        config.validate().expect("file-backed connector credentials are valid");

        config.authz.principal_discovery.keycloak[0].auth.client_secret =
            "ambiguous-inline-secret".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn skips_disabled_federated_connector_entries() {
        let mut config = AppConfigProperties::default();
        // Incomplete on purpose: a disabled entry must not be validated.
        config.authz.principal_discovery.keycloak =
            vec![KeycloakPrincipalDiscoveryProperties::default()];
        config.authz.principal_discovery.ldap = vec![LdapPrincipalDiscoveryProperties::default()];
        config.authz.principal_discovery.custom =
            vec![CustomPrincipalDiscoveryProperties::default()];

        config.validate().expect("disabled federated entries are skipped");
    }

    #[test]
    fn rejects_multiple_enabled_connectors_of_one_protocol() {
        let keycloak = |discovery_id: &str| KeycloakPrincipalDiscoveryProperties {
            enabled: true,
            discovery_id: discovery_id.to_string(),
            base_url: "https://sso.example.com".to_string(),
            realm: "example-corp".to_string(),
            auth: OidcClientCredentialsProperties {
                client_id: "authguard-search".to_string(),
                client_secret: "not-logged-secret".to_string(),
                ..OidcClientCredentialsProperties::default()
            },
            ..KeycloakPrincipalDiscoveryProperties::default()
        };

        // Two enabled connectors of the same protocol are ambiguous by
        // definition: search candidates must map to exactly one source.
        let mut config = AppConfigProperties::default();
        config.authz.principal_discovery.keycloak =
            vec![keycloak("corporate-keycloak"), keycloak("partner-keycloak")];
        assert!(config.validate().is_err());

        // One per protocol stays valid and unambiguous.
        config.authz.principal_discovery.keycloak = vec![keycloak("corporate-keycloak")];
        config.validate().expect("one enabled connector per protocol is valid");
    }

    #[test]
    fn validates_resign_configuration() {
        let mut config = AppConfigProperties::default();
        config.validate().expect("resign JWT is disabled by default");

        config.authz.resign.enabled = true;
        config.authz.resign.private_key_b64 = "bm90IGEga2V5".to_string();
        config.authz.resign.max_ttl = Duration::ZERO;
        assert!(config.validate().is_err(), "positive ttl is required");

        config.authz.resign.max_ttl = Duration::from_secs(60);
        config.validate().expect("inline private key is valid");
    }
}
