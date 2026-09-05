//! Application performance monitoring: structured tracing telemetry and the
//! process-wide Prometheus metrics registry.
//!
//! [`APMComponent`] owns the startup and shutdown of both resources so the
//! server only passes the relevant config sub-objects here.

mod metrics;
mod telemetry;

pub use metrics::MetricsRegistry;
pub use telemetry::{init_telemetry, TelemetryConfig, TelemetryError, TelemetryGuard};

use crate::config::{LoggingConfig, OtelConfig, ServerConfig};

/// Process-wide APM resources: the tracing subscriber and the metrics registry.
pub struct APMComponent {
    telemetry: TelemetryGuard,
    metrics: MetricsRegistry,
}

impl APMComponent {
    /// Installs structured tracing (with OTLP export when configured) and
    /// creates the Prometheus metrics registry.
    ///
    /// # Errors
    ///
    /// Returns an error when the OTLP exporter cannot be built or another
    /// global tracing subscriber is already installed.
    pub fn open(
        server: &ServerConfig,
        logging: &LoggingConfig,
        otel: &OtelConfig,
    ) -> Result<Self, TelemetryError> {
        let telemetry = init_telemetry(&TelemetryConfig::from_settings(server, logging, otel))?;
        Ok(Self { telemetry, metrics: MetricsRegistry::default() })
    }

    #[must_use]
    pub fn metrics(&self) -> MetricsRegistry {
        self.metrics.clone()
    }

    /// Flushes and shuts down the tracing provider before process exit.
    pub fn shutdown(self) {
        self.telemetry.shutdown();
    }
}
