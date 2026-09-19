//! Product-wide configuration constants.

/// Default path mounted into both `AuthGuard` services.
pub const DEFAULT_CONFIG: &str = "/etc/authguard/authguard.yaml";

/// Built-in baseline used when the default path is not mounted, such as unit tests.
pub(crate) const DEFAULT_CONFIG_YAML: &str = include_str!("../../../../etc/authguard.yaml");

/// Environment prefix used for Spring Boot-like nested property overrides.
pub const ENV_PREFIX: &str = "AUTHGUARD__";

/// Optional `KEY=VALUE` secret projection, represented by the typed
/// `secrets.env_file` configuration property.
pub const SECRETS_ENV_FILE_ENV: &str = "AUTHGUARD__SECRETS__ENV_FILE";
