use authguard_adapter_rust::{HttpHeaderAccessFilter, RequestAccess};
use authguard_common::apm::propagate_http_trace_context;
use axum::{
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};

use crate::{
    authorization::resign_token::ResignTokenVerifier,
    dto::{
        CreateCustomerGrowthJobRequest, CustomerGrowthJobDto, CustomerGrowthJobSearchRequest,
        UpdateCustomerGrowthJobRequest,
    },
    repository::CustomerGrowthJobRepository,
};

use super::CustomerGrowthJobController;

#[derive(Clone)]
struct HttpState {
    controller: CustomerGrowthJobController,
    repository: CustomerGrowthJobRepository,
    access_filter: HttpHeaderAccessFilter,
    resign_verifier: Option<ResignTokenVerifier>,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

pub fn routes(
    controller: CustomerGrowthJobController,
    repository: CustomerGrowthJobRepository,
    access_filter: HttpHeaderAccessFilter,
    resign_verifier: Option<ResignTokenVerifier>,
) -> Router {
    let state = HttpState { controller, repository, access_filter, resign_verifier };
    Router::new()
        .route("/healthz", get(health))
        .route("/customer-growth/jobs", get(list_jobs).post(create_job))
        .route("/customer-growth/jobs/{id}", get(get_job).put(update_job).delete(delete_job))
        .layer(middleware::from_fn_with_state(state.clone(), verify_resign_token))
        .layer(middleware::from_fn(propagate_http_trace_context))
        .with_state(state)
}

async fn health(State(state): State<HttpState>) -> Result<&'static str, ApiError> {
    state.repository.ping().await.map_err(|error| ApiError::internal(&error))?;
    Ok("ok")
}

async fn list_jobs(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<CustomerGrowthJobSearchRequest>,
) -> Result<Json<Vec<CustomerGrowthJobDto>>, ApiError> {
    let access = resolve_access(&state.access_filter, &headers).await?;
    state
        .controller
        .list_visible_jobs(&access, &query)
        .await
        .map(Json)
        .map_err(|error| ApiError::service(&error))
}

async fn get_job(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<CustomerGrowthJobDto>, ApiError> {
    let access = resolve_access(&state.access_filter, &headers).await?;
    state
        .controller
        .get_job(&access, id)
        .await
        .map_err(|error| ApiError::service(&error))?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("customer growth job not found or not authorized"))
}

async fn create_job(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<CreateCustomerGrowthJobRequest>,
) -> Result<Json<CustomerGrowthJobDto>, ApiError> {
    let access = resolve_access(&state.access_filter, &headers).await?;
    state
        .controller
        .create_job(&access, request)
        .await
        .map(Json)
        .map_err(|error| ApiError::service(&error))
}

async fn update_job(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<UpdateCustomerGrowthJobRequest>,
) -> Result<Json<CustomerGrowthJobDto>, ApiError> {
    let access = resolve_access(&state.access_filter, &headers).await?;
    state
        .controller
        .update_job(&access, id, request)
        .await
        .map(Json)
        .map_err(|error| ApiError::service(&error))
}

async fn delete_job(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let access = resolve_access(&state.access_filter, &headers).await?;
    state.controller.delete_job(&access, id).await.map_err(|error| ApiError::service(&error))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn verify_resign_token(
    State(state): State<HttpState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if request.uri().path() != "/healthz" {
        if let Some(verifier) = &state.resign_verifier {
            verifier.verify(&request).map_err(|error| {
                tracing::warn!(
                    event = "authguard.resign_token.verification.failed",
                    http.request.path = request.uri().path(),
                    %error,
                    "rejected request without a valid Authguard resign JWT"
                );
                ApiError::new(StatusCode::UNAUTHORIZED, format!("invalid resign JWT: {error}"))
            })?;
        }
    }
    Ok(next.run(request).await)
}

async fn resolve_access(
    filter: &HttpHeaderAccessFilter,
    headers: &HeaderMap,
) -> Result<RequestAccess, ApiError> {
    let scope = filter.enter_headers(headers).await.map_err(|error| {
        ApiError::new(StatusCode::UNAUTHORIZED, format!("invalid access context: {error}"))
    })?;
    scope
        .request_access()
        .cloned()
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "access context is required"))
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self { status, message: message.into() }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    fn internal(error: &anyhow::Error) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
    }

    fn service(error: &anyhow::Error) -> Self {
        let message = error.to_string();
        if message.contains("not found") || message.contains("not authorized") {
            Self::new(StatusCode::NOT_FOUND, message)
        } else if message.contains("action mismatch") || message.contains("access context") {
            Self::new(StatusCode::FORBIDDEN, message)
        } else {
            Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}
