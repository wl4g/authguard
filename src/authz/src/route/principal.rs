//! Principal management and re-discovery routes.

#![allow(clippy::unused_async)] // Axum handlers must return futures.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use crate::handler::{PrincipalHandler, PrincipalHandlerError};
use crate::model::PrincipalStatus;
use crate::principal::{
    PrincipalMaterializationRequest, PrincipalSearchQuery, ScimProvisioningRequest,
};

use super::ApiError;

#[derive(Clone)]
struct PrincipalRouteState {
    handler: PrincipalHandler,
}

pub struct PrincipalRoutes {
    state: PrincipalRouteState,
}

#[derive(Debug, Deserialize)]
struct LocalPrincipalQuery {
    #[serde(default)]
    query: String,
    after_id: Option<String>,
    #[serde(default = "PrincipalRoutes::default_limit")]
    limit: u32,
}

#[derive(Debug, Deserialize)]
struct PrincipalStatusUpdate {
    status: PrincipalStatus,
}

impl PrincipalRoutes {
    #[must_use]
    pub fn new(handler: PrincipalHandler) -> Self {
        Self { state: PrincipalRouteState { handler } }
    }

    pub fn router(self) -> Router {
        Router::new()
            .route("/api/v1/principals", get(Self::list))
            .route(
                "/api/v1/principals/{principal_id}",
                get(Self::get).patch(Self::update_status).delete(Self::delete),
            )
            .route("/api/v1/principal-discovery/search", post(Self::search))
            .route("/api/v1/principal-discovery/materialize", post(Self::materialize))
            .route("/api/v1/principal-discovery/scim/events", post(Self::provision_scim))
            .with_state(self.state)
    }

    async fn list(
        State(state): State<PrincipalRouteState>,
        Query(query): Query<LocalPrincipalQuery>,
    ) -> Response {
        match state.handler.list_page(&query.query, query.after_id.as_deref(), query.limit).await {
            Ok(page) => Json(page).into_response(),
            Err(error) => Self::principal_error(&error),
        }
    }

    async fn get(
        State(state): State<PrincipalRouteState>,
        Path(principal_id): Path<String>,
    ) -> Response {
        match state.handler.get(&principal_id).await {
            Ok(Some(principal)) => Json(principal).into_response(),
            Ok(None) => Self::principal_error(&PrincipalHandlerError::NotFound(principal_id)),
            Err(error) => Self::principal_error(&error),
        }
    }

    async fn update_status(
        State(state): State<PrincipalRouteState>,
        Path(principal_id): Path<String>,
        Json(update): Json<PrincipalStatusUpdate>,
    ) -> Response {
        state.handler.update_status(&principal_id, update.status).await.map_or_else(
            |error| Self::principal_error(&error),
            |principal| Json(principal).into_response(),
        )
    }

    async fn delete(
        State(state): State<PrincipalRouteState>,
        Path(principal_id): Path<String>,
    ) -> Response {
        state.handler.delete(&principal_id).await.map_or_else(
            |error| Self::principal_error(&error),
            |()| StatusCode::NO_CONTENT.into_response(),
        )
    }

    async fn search(
        State(state): State<PrincipalRouteState>,
        Json(query): Json<PrincipalSearchQuery>,
    ) -> Response {
        state
            .handler
            .search(query)
            .await
            .map_or_else(|error| Self::principal_error(&error), |page| Json(page).into_response())
    }

    async fn materialize(
        State(state): State<PrincipalRouteState>,
        Json(request): Json<PrincipalMaterializationRequest>,
    ) -> Response {
        state.handler.materialize(&request).await.map_or_else(
            |error| Self::principal_error(&error),
            |principal| (StatusCode::CREATED, Json(principal)).into_response(),
        )
    }

    async fn provision_scim(
        State(state): State<PrincipalRouteState>,
        Json(request): Json<ScimProvisioningRequest>,
    ) -> Response {
        state.handler.provision_scim(request).await.map_or_else(
            |error| Self::principal_error(&error),
            |principal| Json(principal).into_response(),
        )
    }
    const fn default_limit() -> u32 {
        20
    }

    fn principal_error(error: &PrincipalHandlerError) -> Response {
        let (status, code) = match error {
            PrincipalHandlerError::NotFound(_) => (StatusCode::NOT_FOUND, "principal_not_found"),
            PrincipalHandlerError::Disabled(_) => (StatusCode::CONFLICT, "principal_disabled"),
            PrincipalHandlerError::KindMismatch(_) => {
                (StatusCode::CONFLICT, "principal_kind_mismatch")
            }
            PrincipalHandlerError::Referenced(_) => {
                (StatusCode::CONFLICT, "principal_still_referenced")
            }
            PrincipalHandlerError::ProviderUnavailable => {
                (StatusCode::SERVICE_UNAVAILABLE, "principal_discovery_unavailable")
            }
            PrincipalHandlerError::Discovery(_) => {
                (StatusCode::BAD_GATEWAY, "principal_discovery_failed")
            }
            PrincipalHandlerError::Storage(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, "principal_storage_unavailable")
            }
        };
        if matches!(error, PrincipalHandlerError::Storage(_)) {
            tracing::error!(
                authguard.principal.error_code = code,
                %error,
                "principal operation failed because storage is unavailable"
            );
        } else {
            tracing::warn!(
                authguard.principal.error_code = code,
                %error,
                "principal operation rejected"
            );
        }
        (status, Json(ApiError::new(code, error.to_string()))).into_response()
    }
}
