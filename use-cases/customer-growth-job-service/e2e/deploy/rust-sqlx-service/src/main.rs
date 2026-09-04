use std::{env, sync::Arc};

use authguard_adapter_rust::{
    GrpcAccessContextResolver, HeaderAccessContextResolver, HttpHeaderAccessFilter,
    IAccessContextResolver, RequestAccess, GRPC_TARGET_ENV,
};
use authguard_customer_growth_job_rust_service::{
    customer_growth_job_controller::CustomerGrowthJobController,
    customer_growth_job_dto::{
        CreateCustomerGrowthJobRequest, CustomerGrowthJobSearchRequest,
        UpdateCustomerGrowthJobRequest,
    },
    customer_growth_job_repository::CustomerGrowthJobRepository,
    customer_growth_job_service::CustomerGrowthJobService,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use sqlx::any::AnyPoolOptions;

#[derive(Clone)]
struct AppState {
    controller: CustomerGrowthJobController,
    repository: CustomerGrowthJobRepository,
    access_filter: HttpHeaderAccessFilter,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sqlx::any::install_default_drivers();
    let database_url = required_env("DATABASE_URL")?;
    let pool =
        AnyPoolOptions::new().max_connections(16).min_connections(1).connect(&database_url).await?;
    let repository = CustomerGrowthJobRepository::new(pool);
    repository.ping().await?;
    let controller =
        CustomerGrowthJobController::new(CustomerGrowthJobService::new(repository.clone()));
    let state = AppState { controller, repository, access_filter: access_filter_from_env()? };

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/customer-growth/jobs", get(list_jobs).post(create_job))
        .route("/customer-growth/jobs/{id}", get(get_job).put(update_job).delete(delete_job))
        .with_state(state);
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health(State(state): State<AppState>) -> Result<&'static str, ApiError> {
    state.repository.ping().await.map_err(|error| ApiError::internal(&error))?;
    Ok("ok")
}

async fn list_jobs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CustomerGrowthJobSearchRequest>,
) -> Result<Json<Vec<authguard_customer_growth_job_rust_service::customer_growth_job_dto::CustomerGrowthJobDto>>, ApiError>{
    let access = resolve_access(&state.access_filter, &headers).await?;
    Ok(Json(
        state
            .controller
            .list_visible_jobs(&access, &query)
            .await
            .map_err(|error| ApiError::service(&error))?,
    ))
}

async fn get_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<
    Json<authguard_customer_growth_job_rust_service::customer_growth_job_dto::CustomerGrowthJobDto>,
    ApiError,
> {
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
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateCustomerGrowthJobRequest>,
) -> Result<
    Json<authguard_customer_growth_job_rust_service::customer_growth_job_dto::CustomerGrowthJobDto>,
    ApiError,
> {
    let access = resolve_access(&state.access_filter, &headers).await?;
    Ok(Json(
        state
            .controller
            .create_job(&access, request)
            .await
            .map_err(|error| ApiError::service(&error))?,
    ))
}

async fn update_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<UpdateCustomerGrowthJobRequest>,
) -> Result<
    Json<authguard_customer_growth_job_rust_service::customer_growth_job_dto::CustomerGrowthJobDto>,
    ApiError,
> {
    let access = resolve_access(&state.access_filter, &headers).await?;
    Ok(Json(
        state
            .controller
            .update_job(&access, id, request)
            .await
            .map_err(|error| ApiError::service(&error))?,
    ))
}

async fn delete_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let access = resolve_access(&state.access_filter, &headers).await?;
    state.controller.delete_job(&access, id).await.map_err(|error| ApiError::service(&error))?;
    Ok(StatusCode::NO_CONTENT)
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

fn access_filter_from_env() -> anyhow::Result<HttpHeaderAccessFilter> {
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

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
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

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.status, self.message).into_response()
    }
}
