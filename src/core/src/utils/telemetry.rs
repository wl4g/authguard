use std::time::Duration;

use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::Sampler;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use thiserror::Error;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, Registry};

#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    pub service_name: String,
    pub service_version: String,
    pub environment: String,
    pub env_filter: String,
    pub json: bool,
    pub otlp_endpoint: Option<String>,
    pub export_timeout: Duration,
    pub sample_rate: f64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: "authguard".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            environment: "development".to_string(),
            env_filter: "info,tower_http=info".to_string(),
            json: false,
            otlp_endpoint: None,
            export_timeout: Duration::from_secs(5),
            sample_rate: 1.0,
        }
    }
}

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("build OTLP trace exporter: {0}")]
    Exporter(#[from] opentelemetry_otlp::ExporterBuildError),
    #[error("install tracing subscriber: {0}")]
    Subscriber(#[from] tracing_subscriber::util::TryInitError),
}

#[derive(Debug, Default)]
pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

impl TelemetryGuard {
    pub fn shutdown(mut self) {
        if let Some(provider) = self.provider.take() {
            let _ = provider.shutdown();
        }
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            let _ = provider.shutdown();
        }
    }
}

/// Installs structured tracing and, when configured, an OTLP gRPC exporter.
///
/// # Errors
///
/// Returns an error when the exporter cannot be built or another global tracing
/// subscriber is already installed.
pub fn init_telemetry(config: &TelemetryConfig) -> Result<TelemetryGuard, TelemetryError> {
    global::set_text_map_propagator(TraceContextPropagator::new());
    let filter = EnvFilter::try_new(&config.env_filter).unwrap_or_else(|_| EnvFilter::new("info"));

    let provider = if let Some(endpoint) = config.otlp_endpoint.as_deref() {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .with_timeout(config.export_timeout)
            .build()?;
        let resource = Resource::builder()
            .with_service_name(config.service_name.clone())
            .with_attributes([
                KeyValue::new("service.version", config.service_version.clone()),
                KeyValue::new("deployment.environment.name", config.environment.clone()),
            ])
            .build();
        Some(
            SdkTracerProvider::builder()
                .with_resource(resource)
                .with_sampler(Sampler::TraceIdRatioBased(config.sample_rate))
                .with_batch_exporter(exporter)
                .build(),
        )
    } else {
        None
    };

    match (provider.as_ref(), config.json) {
        (Some(provider), true) => {
            let tracer = provider.tracer("authguard");
            Registry::default()
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .with(filter)
                .with(fmt::layer().json())
                .try_init()?;
        }
        (Some(provider), false) => {
            let tracer = provider.tracer("authguard");
            Registry::default()
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .with(filter)
                .with(fmt::layer())
                .try_init()?;
        }
        (None, true) => Registry::default().with(filter).with(fmt::layer().json()).try_init()?,
        (None, false) => Registry::default().with(filter).with(fmt::layer()).try_init()?,
    }

    tracing::info!(
        service.name = %config.service_name,
        service.version = %config.service_version,
        deployment.environment.name = %config.environment,
        otel.enabled = provider.is_some(),
        "telemetry initialized"
    );
    Ok(TelemetryGuard { provider })
}
