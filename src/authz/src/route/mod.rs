pub mod authorization;
pub mod policy;
pub mod principal;

use std::sync::Arc;

use authguard_common::apm::metrics::AuthzMetrics;
use axum::extract::{MatchedPath, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};

use self::policy::PolicyRoutes;
use self::principal::PrincipalRoutes;
use crate::handler::{PolicyHandler, PrincipalHandler};

/// Authenticated composition of `AuthGuard`'s control-plane APIs.
pub struct ApiRoutes {
    policy: PolicyHandler,
    principals: PrincipalHandler,
    authenticator: ApiAuthenticator,
}

#[derive(Clone)]
pub struct ApiAuthenticator {
    token: Option<Arc<str>>,
}

#[derive(Clone)]
pub struct HttpMetrics {
    metrics: AuthzMetrics,
}

#[derive(Debug, serde::Serialize)]
struct ApiError {
    code: String,
    message: String,
}

impl ApiError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self { code: code.into(), message: message.into() }
    }
}

impl ApiAuthenticator {
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
            tracing::warn!("rejected control-plane request because the API is disabled");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError::new("api_disabled", "control-plane credential is not configured")),
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
                    "invalid_api_token",
                    "valid control-plane bearer token required",
                )),
            )
                .into_response();
            response.headers_mut().insert(
                "www-authenticate",
                HeaderValue::from_static("Bearer realm=\"authguard-api\""),
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

impl ApiRoutes {
    #[must_use]
    pub fn new(
        policy: PolicyHandler,
        principals: PrincipalHandler,
        api_token: Option<String>,
    ) -> Self {
        Self { policy, principals, authenticator: ApiAuthenticator::new(api_token) }
    }

    pub fn router(self) -> Router {
        PolicyRoutes::new(self.policy)
            .router()
            .merge(PrincipalRoutes::new(self.principals).router())
            .route_layer(middleware::from_fn_with_state(
                self.authenticator,
                ApiAuthenticator::authenticate,
            ))
    }
}

impl HttpMetrics {
    #[must_use]
    pub fn new(metrics: AuthzMetrics) -> Self {
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

pub use authorization::EnvoyAuthzRoutes;

#[cfg(test)]
mod tests {
    use super::ApiAuthenticator;

    #[test]
    fn compares_api_tokens_without_early_byte_exit() {
        assert!(ApiAuthenticator::constant_time_eq(b"secret", b"secret"));
        assert!(!ApiAuthenticator::constant_time_eq(b"secret", b"secrex"));
        assert!(!ApiAuthenticator::constant_time_eq(b"secret", b"short"));
    }
}
