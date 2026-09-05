use std::sync::Arc;
use std::time::Duration;

use crate::apm::MetricsRegistry;
use crate::cache::IAuthorizationCache;
use crate::handler::PolicyHandler;

#[derive(Clone)]
pub struct ManagementHandler {
    cache: Arc<dyn IAuthorizationCache>,
    policy: PolicyHandler,
    policy_max_staleness: Duration,
    metrics: MetricsRegistry,
}

impl ManagementHandler {
    #[must_use]
    pub fn new(
        cache: Arc<dyn IAuthorizationCache>,
        policy: PolicyHandler,
        policy_max_staleness: Duration,
        metrics: MetricsRegistry,
    ) -> Self {
        Self { cache, policy, policy_max_staleness, metrics }
    }

    /// Verifies cache and durable-storage connectivity plus policy freshness.
    ///
    /// # Errors
    ///
    /// Returns the provider error when readiness cannot be established.
    pub async fn readiness(&self) -> anyhow::Result<()> {
        self.cache.ping().await?;
        self.policy.readiness(self.policy_max_staleness).await
    }

    /// Renders the current `OpenMetrics` document.
    ///
    /// # Errors
    ///
    /// Returns an encoding error when metrics cannot be rendered.
    pub fn metrics(&self) -> anyhow::Result<String> {
        Ok(self.metrics.render()?)
    }
}
