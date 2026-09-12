use std::{env, sync::Arc};

use authguard_adapter_rust::{
    GrpcAccessContextResolver, HeaderAccessContextResolver, HttpHeaderAccessFilter,
    IAccessContextResolver, GRPC_TARGET_ENV,
};

#[derive(Debug, Clone)]
pub struct AppProperties {
    pub database_url: String,
    pub port: u16,
}

impl AppProperties {
    /// Loads the small business-service runtime configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when required environment values are absent or malformed.
    pub fn load() -> anyhow::Result<Self> {
        let database_url = required_env("DATABASE_URL")?;
        let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string()).parse::<u16>()?;
        Ok(Self { database_url, port })
    }
}

/// Builds the SDK access-context chain used at the HTTP boundary.
///
/// # Errors
///
/// Returns an error when a configured resolver is invalid.
pub fn access_filter() -> anyhow::Result<HttpHeaderAccessFilter> {
    let mut resolvers: Vec<Arc<dyn IAccessContextResolver>> =
        vec![Arc::new(HeaderAccessContextResolver::from_env()?)];
    if env::var(GRPC_TARGET_ENV).is_ok_and(|value| !value.trim().is_empty()) {
        resolvers.push(Arc::new(GrpcAccessContextResolver::from_env()?));
    }
    Ok(HttpHeaderAccessFilter::new(resolvers))
}

fn required_env(name: &str) -> anyhow::Result<String> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("{name} is required"))
}
