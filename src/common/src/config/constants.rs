//! Product-wide configuration constants.

/// Default path mounted into both `AuthGuard` services.
pub const DEFAULT_CONFIG: &str = "/etc/authguard/authguard.yaml";

/// Built-in baseline used when the default path is not mounted, such as unit tests.
pub(crate) const DEFAULT_CONFIG_YAML: &str = include_str!("../../../../etc/authguard.yaml");

/// Environment prefix used for Spring Boot-like nested property overrides.
pub const ENV_PREFIX: &str = "AUTHGUARD__";

/// Shared configuration file environment variable.
pub const CONFIG_FILE_ENV: &str = "AUTHGUARD_CONFIG_FILE";

/// Optional `KEY=VALUE` secret projection environment variable.
pub const SECRET_ENV_FILE_ENV: &str = "AUTHGUARD_ENV_FILE";
