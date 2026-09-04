use std::sync::{Arc, Mutex};

use prometheus_client::encoding::text::encode;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct DecisionLabels {
    decision: String,
    reason: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct HttpLabels {
    route: String,
    method: String,
    status: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ReloadLabels {
    outcome: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct DeliveryLabels {
    mode: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ResolutionLabels {
    outcome: String,
}

#[derive(Clone, Debug)]
pub struct MetricsRegistry {
    registry: Arc<Mutex<Registry>>,
    authorization_decisions: Family<DecisionLabels, Counter>,
    authorization_duration: Histogram,
    http_requests: Family<HttpLabels, Counter>,
    policy_reloads: Family<ReloadLabels, Counter>,
    policy_revision: Gauge,
    scope_deliveries: Family<DeliveryLabels, Counter>,
    scope_resolutions: Family<ResolutionLabels, Counter>,
    scope_resolution_duration: Histogram,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        let authorization_decisions = Family::default();
        let authorization_duration = Histogram::new(exponential_buckets(0.000_25, 2.0, 14));
        let http_requests = Family::default();
        let policy_reloads = Family::default();
        let policy_revision = Gauge::default();
        let scope_deliveries = Family::default();
        let scope_resolutions = Family::default();
        let scope_resolution_duration = Histogram::new(exponential_buckets(0.000_25, 2.0, 14));

        let mut registry = Registry::default();
        registry.register(
            "authguard_authorization_decisions",
            "Authorization decisions by outcome and bounded reason",
            authorization_decisions.clone(),
        );
        registry.register(
            "authguard_authorization_duration_seconds",
            "Authorization decision latency in seconds",
            authorization_duration.clone(),
        );
        registry.register(
            "authguard_http_requests",
            "HTTP requests by stable route, method, and status",
            http_requests.clone(),
        );
        registry.register(
            "authguard_policy_reloads",
            "Policy snapshot reload attempts by outcome",
            policy_reloads.clone(),
        );
        registry.register(
            "authguard_policy_revision",
            "Current in-memory authorization policy revision",
            policy_revision.clone(),
        );
        registry.register(
            "authguard_scope_deliveries",
            "Authorization scope deliveries by direct context or opaque token mode",
            scope_deliveries.clone(),
        );
        registry.register(
            "authguard_scope_resolutions",
            "Opaque scope token resolutions by bounded outcome",
            scope_resolutions.clone(),
        );
        registry.register(
            "authguard_scope_resolution_duration_seconds",
            "Opaque scope token resolution latency in seconds",
            scope_resolution_duration.clone(),
        );

        Self {
            registry: Arc::new(Mutex::new(registry)),
            authorization_decisions,
            authorization_duration,
            http_requests,
            policy_reloads,
            policy_revision,
            scope_deliveries,
            scope_resolutions,
            scope_resolution_duration,
        }
    }
}

impl MetricsRegistry {
    pub fn record_authorization(&self, allowed: bool, reason: &str, seconds: f64) {
        let labels = DecisionLabels {
            decision: if allowed { "allow" } else { "deny" }.to_string(),
            reason: bounded_reason(reason).to_string(),
        };
        self.authorization_decisions.get_or_create(&labels).inc();
        self.authorization_duration.observe(seconds);
    }

    pub fn record_http(&self, route: &str, method: &str, status: u16) {
        let labels = HttpLabels {
            route: route.to_string(),
            method: method.to_string(),
            status: status.to_string(),
        };
        self.http_requests.get_or_create(&labels).inc();
    }

    pub fn record_policy_reload(&self, succeeded: bool) {
        let labels =
            ReloadLabels { outcome: if succeeded { "success" } else { "failure" }.to_string() };
        self.policy_reloads.get_or_create(&labels).inc();
    }

    pub fn set_policy_revision(&self, revision: u64) {
        self.policy_revision.set(i64::try_from(revision).unwrap_or(i64::MAX));
    }

    pub fn record_scope_delivery(&self, mode: &str) {
        let mode = match mode {
            "direct" => "direct",
            "token" => "token",
            _ => "other",
        };
        self.scope_deliveries.get_or_create(&DeliveryLabels { mode: mode.to_string() }).inc();
    }

    pub fn record_scope_resolution(&self, outcome: &str, seconds: f64) {
        let outcome = match outcome {
            "hit" => "hit",
            "miss" => "miss",
            "invalid" => "invalid",
            "error" => "error",
            _ => "other",
        };
        self.scope_resolutions
            .get_or_create(&ResolutionLabels { outcome: outcome.to_string() })
            .inc();
        self.scope_resolution_duration.observe(seconds);
    }

    /// Encodes all registered metrics in `OpenMetrics` text format.
    ///
    /// # Errors
    ///
    /// Returns a formatting error if a metric cannot be encoded.
    pub fn render(&self) -> Result<String, std::fmt::Error> {
        let registry = self.registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut body = String::new();
        encode(&mut body, &registry)?;
        Ok(body)
    }
}

fn bounded_reason(reason: &str) -> &'static str {
    match reason {
        "matched role binding" => "matched_role_binding",
        "explicit deny" => "explicit_deny",
        "default deny" => "default_deny",
        "missing identity" => "missing_identity",
        "invalid identity" => "invalid_identity",
        "route not mapped" => "route_not_mapped",
        "invalid resource urn" => "invalid_resource_urn",
        "invalid request" => "invalid_request",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_bounded_authorization_and_http_metrics() {
        let metrics = MetricsRegistry::default();
        metrics.record_authorization(true, "matched role binding", 0.001);
        metrics.record_http("auth_check", "GET", 200);
        metrics.record_policy_reload(true);
        metrics.set_policy_revision(3);
        metrics.record_scope_delivery("token");
        metrics.record_scope_resolution("hit", 0.002);

        let body = metrics.render().expect("metrics");
        assert!(body.contains("authguard_authorization_decisions_total{decision=\"allow\",reason=\"matched_role_binding\"} 1"));
        assert!(body.contains(
            "authguard_http_requests_total{route=\"auth_check\",method=\"GET\",status=\"200\"} 1"
        ));
        assert!(body.contains("authguard_policy_revision 3"));
        assert!(body.contains("authguard_scope_deliveries_total{mode=\"token\"} 1"));
        assert!(body.contains("authguard_scope_resolutions_total{outcome=\"hit\"} 1"));
    }
}
