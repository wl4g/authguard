use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{MatchedPath, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use opentelemetry::global;
use opentelemetry_http::HeaderExtractor;
use tracing::Instrument as _;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

use crate::model::ApiError;
use crate::utils::MetricsRegistry;

#[derive(Clone)]
pub struct AdminAuthenticator {
    token: Option<Arc<str>>,
}

impl AdminAuthenticator {
    #[must_use]
    pub fn new(token: Option<String>) -> Self {
        Self { token: token.filter(|token| !token.is_empty()).map(Arc::from) }
    }

    pub async fn authenticate(
        State(authenticator): State<Self>,
        request: Request,
        next: Next,
    ) -> Response {
        let Some(expected) = authenticator.token.as_deref() else {
            tracing::warn!("rejected control-plane request because the admin API is disabled");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::new(
                    "admin_api_disabled",
                    "control-plane credential is not configured",
                )),
            )
                .into_response();
        };
        let provided = request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        if !provided.is_some_and(|provided| {
            Self::constant_time_eq(provided.as_bytes(), expected.as_bytes())
        }) {
            tracing::warn!("rejected control-plane request with invalid credentials");
            let mut response = (
                StatusCode::UNAUTHORIZED,
                Json(ApiError::new(
                    "invalid_admin_token",
                    "valid control-plane bearer token required",
                )),
            )
                .into_response();
            response.headers_mut().insert(
                "www-authenticate",
                HeaderValue::from_static("Bearer realm=\"authguard-admin\""),
            );
            return response;
        }
        next.run(request).await
    }

    fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
        if left.len() != right.len() {
            return false;
        }
        left.iter().zip(right).fold(0_u8, |difference, (left, right)| difference | left ^ right)
            == 0
    }
}

#[derive(Clone)]
pub struct HttpMetrics {
    metrics: MetricsRegistry,
}

impl HttpMetrics {
    #[must_use]
    pub fn new(metrics: MetricsRegistry) -> Self {
        Self { metrics }
    }

    pub async fn observe(State(state): State<Self>, request: Request, next: Next) -> Response {
        let method = request.method().as_str().to_string();
        let route = request
            .extensions()
            .get::<MatchedPath>()
            .map_or_else(|| "unmatched".to_string(), |path| path.as_str().to_string());
        let response = next.run(request).await;
        state.metrics.record_http(&route, &method, response.status().as_u16());
        response
    }
}

pub struct TraceContext;

impl TraceContext {
    pub async fn propagate(request: Request<Body>, next: Next) -> Response {
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
                http.response.status_code = response.status().as_u16(),
                duration_seconds = started.elapsed().as_secs_f64(),
                "management HTTP request completed"
            );
            response
        }
        .instrument(span.clone())
        .await;
        span.record("http.response.status_code", response.status().as_u16());
        response
    }
}

#[cfg(test)]
mod tests {
    use super::AdminAuthenticator;

    #[test]
    fn compares_admin_tokens_without_early_byte_exit() {
        assert!(AdminAuthenticator::constant_time_eq(b"secret", b"secret"));
        assert!(!AdminAuthenticator::constant_time_eq(b"secret", b"secrex"));
        assert!(!AdminAuthenticator::constant_time_eq(b"secret", b"short"));
    }
}
