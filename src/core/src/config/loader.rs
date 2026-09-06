use std::collections::HashMap;
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
    /// `AUTHGUARD_ENV_FILE` selects a Secret-style `KEY=VALUE` file (e.g. the
    /// GCP Secret Manager value or the Kubernetes Secret `envFrom` volume);
    /// values referenced in the YAML as `${KEY}` are resolved from it.
    ///
    /// # Errors
    ///
    /// Returns an error for unreadable files, unknown keys, invalid values, or
    /// an unsafe runtime configuration.
    pub fn load() -> anyhow::Result<Self> {
        let env_values = read_env_file(std::env::var("AUTHGUARD_ENV_FILE").ok().as_deref())?;
        let mut builder = ::config::Config::builder()
            .add_source(File::from_str(DEFAULT_CONFIG, FileFormat::Yaml));
        if let Ok(path) = std::env::var("AUTHGUARD_CONFIG_FILE") {
            builder = builder.add_source(File::from(Path::new(&path)).required(true));
        }
        let mut config = builder
            .add_source(
                Environment::with_prefix("AUTHGUARD")
                    .prefix_separator("__")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()
            .context("build Authguard configuration")?;
        expand_env_refs(&mut config.cache, &env_values)
            .context("resolve ${KEY} references in Authguard configuration")?;
        let config = config.try_deserialize::<Self>().context("decode Authguard configuration")?;
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

/// Reads a Secret-style `KEY=VALUE` env file into a lookup map.
///
/// Lines without `=` (e.g. `export` or `key` shells) are skipped. Missing
/// files are fine: `${KEY}` resolution then falls back to the process
/// environment; an unresolvable reference later fails closed.
fn read_env_file(path: Option<&str>) -> anyhow::Result<HashMap<String, String>> {
    let mut values = HashMap::new();
    if let Some(path) = path {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("read secret env file {path}"))?;
        for line in content.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            values.insert(key.trim().to_string(), value.trim_end().to_string());
        }
    }
    Ok(values)
}

/// Looks up a secret value from the configured `AUTHGUARD_ENV_FILE` first,
/// then from the process environment.
///
/// Shared by the `${KEY}` expansion below and by direct environment consumers
/// such as the access-context signing key, so both resolve secrets uniformly
/// regardless of the injected provider (Kubernetes `envFrom` or a mounted
/// KEY=VALUE file).
pub(crate) fn secret_env(name: &str) -> Option<String> {
    read_env_file(std::env::var("AUTHGUARD_ENV_FILE").ok().as_deref())
        .ok()
        .and_then(|values| values.get(name).cloned())
        .or_else(|| std::env::var(name).ok())
}

/// Resolves `${KEY}` references in every string leaf of the merged
/// configuration cache.
///
/// A value is replaced only when it starts with `${KEY}` and ends with `}`,
/// mirroring the reference format of the Helm-rendered `authguard.yaml`.
/// An unresolved reference is an error — silently keeping the placeholder
/// would deploy a publicly known credential string.
fn expand_env_refs(
    cache: &mut ::config::Value,
    env_values: &HashMap<String, String>,
) -> anyhow::Result<()> {
    match &mut cache.kind {
        ::config::ValueKind::Table(table) => {
            for value in table.values_mut() {
                expand_env_refs(value, env_values)?;
            }
        }
        ::config::ValueKind::Array(items) => {
            for value in items {
                expand_env_refs(value, env_values)?;
            }
        }
        ::config::ValueKind::String(text) => {
            if text.starts_with("${") && text.ends_with('}') {
                let key = &text[2..text.len() - 1];
                let Some(resolved) =
                    env_values.get(key).cloned().or_else(|| std::env::var(key).ok())
                else {
                    anyhow::bail!(
                        "configuration references ${{{key}}} but neither the secret env file nor the process environment provides it"
                    );
                };
                *text = resolved;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string_value(text: &str) -> ::config::Value {
        ::config::Value::new(None, ::config::ValueKind::String(text.to_string()))
    }

    #[test]
    fn env_file_parses_key_value_lines() {
        let dir = std::env::temp_dir().join(format!("authguard-env-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let env_file = dir.join("env");
        std::fs::write(
            &env_file,
            "# comment\nAUTHGUARD_REDIS_PASSWORD=pa55word\nAUTHGUARD_RESIGN_JWT_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        let values = read_env_file(Some(env_file.to_str().unwrap())).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(values.get("AUTHGUARD_REDIS_PASSWORD").map(String::as_str), Some("pa55word"));
        assert!(values.contains_key("AUTHGUARD_RESIGN_JWT_PRIVATE_KEY"));
        assert!(!values.contains_key("# comment"));
    }

    #[test]
    fn env_refs_resolve_in_tables_and_arrays() {
        let values = HashMap::from([
            ("AUTHGUARD_REDIS_PASSWORD".to_string(), "pa55word".to_string()),
            (
                "AUTHGUARD_TRUSTED_ISSUER".to_string(),
                "https://idp.example.com/realms/corp".to_string(),
            ),
        ]);
        let mut cache = ::config::Value::new(
            None,
            ::config::ValueKind::Table(
                [
                    ("password".to_string(), string_value("${AUTHGUARD_REDIS_PASSWORD}")),
                    (
                        "issuers".to_string(),
                        ::config::Value::new(
                            None,
                            ::config::ValueKind::Array(vec![string_value(
                                "${AUTHGUARD_TRUSTED_ISSUER}",
                            )]),
                        ),
                    ),
                ]
                .into_iter()
                .collect(),
            ),
        );
        expand_env_refs(&mut cache, &values).unwrap();
        let ::config::ValueKind::Table(table) = &cache.kind else { unreachable!() };
        assert_eq!(table["password"].kind, ::config::ValueKind::String("pa55word".to_string()));
        let ::config::ValueKind::Array(items) = &table["issuers"].kind else { unreachable!() };
        assert_eq!(
            items[0].kind,
            ::config::ValueKind::String("https://idp.example.com/realms/corp".to_string())
        );
    }

    #[test]
    fn unresolvable_env_ref_fails_closed() {
        let mut cache = string_value("${MISSING_AUTHGUARD_KEY}");
        assert!(expand_env_refs(&mut cache, &HashMap::new()).is_err());
    }

    #[test]
    fn env_refs_fall_back_to_process_environment() {
        // The kubernetes secrets provider injects through envFrom, so the
        // references must resolve from the process environment alone.
        std::env::set_var("AUTHGUARD_TEST_CONNECTOR_SECRET", "process-env-secret");
        let mut cache = string_value("${AUTHGUARD_TEST_CONNECTOR_SECRET}");
        expand_env_refs(&mut cache, &HashMap::new()).unwrap();
        assert_eq!(cache.kind, ::config::ValueKind::String("process-env-secret".to_string()));
        std::env::remove_var("AUTHGUARD_TEST_CONNECTOR_SECRET");
    }
}
