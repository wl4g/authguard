use std::time::Duration;

use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use thiserror::Error;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, Registry};

use crate::{LoggingProperties, OtelProperties};

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

impl TelemetryConfig {
    #[must_use]
    pub fn from_settings(
        service_name: &str,
        logging: &LoggingProperties,
        otel: &OtelProperties,
    ) -> Self {
        Self {
            service_name: service_name.to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            environment: std::env::var("OTEL_RESOURCE_ATTRIBUTES")
                .ok()
                .and_then(|attributes| {
                    find_resource_attribute(&attributes, "deployment.environment.name")
                })
                .unwrap_or_else(|| "production".to_string()),
            env_filter: logging.level.clone(),
            json: logging.mode.eq_ignore_ascii_case("JSON"),
            otlp_endpoint: otel.enabled.then(|| otel.endpoint.clone()),
            export_timeout: otel.timeout,
            sample_rate: otel.sample_rate,
        }
    }
}

fn find_resource_attribute(attributes: &str, name: &str) -> Option<String> {
    attributes.split(',').find_map(|entry| {
        let (key, value) = entry.split_once('=')?;
        (key.trim() == name).then(|| value.trim().to_string())
    })
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

/// Installs structured tracing and an optional OTLP/gRPC exporter.
///
/// # Errors
///
/// Returns an error if the exporter or global subscriber cannot be installed.
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
        (Some(provider), true) => Registry::default()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("authguard")))
            .with(filter)
            .with(fmt::layer().json())
            .try_init()?,
        (Some(provider), false) => Registry::default()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("authguard")))
            .with(filter)
            .with(fmt::layer())
            .try_init()?,
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
use std::time::Instant;

use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use opentelemetry::propagation::Extractor;
use tracing::Instrument as _;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key)?.to_str().ok()
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(axum::http::HeaderName::as_str).collect()
    }
}

/// Extracts W3C Trace Context and creates one server span around an Axum request.
///
/// This protocol-neutral middleware is shared by `AuthN` and `AuthZ` HTTP endpoints.
/// It records only bounded routing metadata; credentials and query values never
/// enter logs or spans.
pub async fn propagate_http_trace_context(request: Request<Body>, next: Next) -> Response {
    const MAX_REQUEST_ID_BYTES: usize = 128;

    let started = Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= MAX_REQUEST_ID_BYTES
                && value.bytes().all(|byte| byte.is_ascii_graphic())
        })
        .unwrap_or("")
        .to_string();
    let parent = global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(request.headers()))
    });
    let span = tracing::info_span!(
        "http.server.request",
        otel.kind = "server",
        http.request.method = %method,
        http.request.id = %request_id,
        url.path = %path,
        http.response.status_code = tracing::field::Empty,
    );
    let _ = span.set_parent(parent);
    let response = async move {
        let response = next.run(request).await;
        tracing::debug!(
            event = "authguard.http.request.completed",
            http.response.status_code = response.status().as_u16(),
            duration_seconds = started.elapsed().as_secs_f64(),
            "HTTP request completed"
        );
        response
    }
    .instrument(span.clone())
    .await;
    span.record("http.response.status_code", response.status().as_u16());
    response
}
