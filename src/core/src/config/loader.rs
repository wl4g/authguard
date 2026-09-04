use std::path::Path;

use ::config::{Environment, File, FileFormat};
use anyhow::Context as _;

use super::AuthguardConfig;

const DEFAULT_CONFIG: &str = include_str!("../../../../etc/authguard.yaml");

impl AuthguardConfig {
    /// Loads the annotated default YAML, an optional file, and environment overrides.
    ///
    /// `AUTHGUARD_CONFIG_FILE` selects a file. Nested overrides use double
    /// underscores, for example `AUTHGUARD__SERVER__PORT=8081`.
    ///
    /// # Errors
    ///
    /// Returns an error for unreadable files, unknown keys, invalid values, or
    /// an unsafe runtime configuration.
    pub fn load() -> anyhow::Result<Self> {
        let mut builder = ::config::Config::builder()
            .add_source(File::from_str(DEFAULT_CONFIG, FileFormat::Yaml));
        if let Ok(path) = std::env::var("AUTHGUARD_CONFIG_FILE") {
            builder = builder.add_source(File::from(Path::new(&path)).required(true));
        }
        let config = builder
            .add_source(
                Environment::with_prefix("AUTHGUARD")
                    .prefix_separator("__")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()
            .context("build Authguard configuration")?
            .try_deserialize::<Self>()
            .context("decode Authguard configuration")?;
        config.validate()?;
        config.validate_deployment(runtime_replica_count()?)?;
        Ok(config)
    }

    /// Loads and validates one explicit YAML file without environment overrides.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown keys or invalid values.
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let config = ::config::Config::builder()
            .add_source(File::from(path.as_ref()).required(true))
            .build()?
            .try_deserialize::<Self>()?;
        config.validate()?;
        Ok(config)
    }

    #[cfg(test)]
    pub(super) fn from_default_yaml() -> anyhow::Result<Self> {
        ::config::Config::builder()
            .add_source(File::from_str(DEFAULT_CONFIG, FileFormat::Yaml))
            .build()?
            .try_deserialize::<Self>()
            .context("decode default Authguard configuration")
    }
}

fn runtime_replica_count() -> anyhow::Result<usize> {
    std::env::var("AUTHGUARD_REPLICA_COUNT").map_or(Ok(1), |value| {
        value.parse::<usize>().with_context(|| "AUTHGUARD_REPLICA_COUNT must be a positive integer")
    })
}
