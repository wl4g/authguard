//! Shared observability infrastructure for both `AuthGuard` services.

pub mod metrics;
pub mod pprof;
pub mod telemetry;

pub use metrics::{AuthnMetrics, AuthzMetrics, MetricsRenderer};
pub use telemetry::{
    init_telemetry, propagate_http_trace_context, TelemetryConfig, TelemetryError, TelemetryGuard,
};
