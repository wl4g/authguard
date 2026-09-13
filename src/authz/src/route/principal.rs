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
use crate::principal::{PrincipalMaterializationRequest, PrincipalSearchQuery};

use super::principal_error;

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
            .with_state(self.state)
    }

    async fn list(
        State(state): State<PrincipalRouteState>,
        Query(query): Query<LocalPrincipalQuery>,
    ) -> Response {
        match state.handler.list_page(&query.query, query.after_id.as_deref(), query.limit).await {
            Ok(page) => Json(page).into_response(),
            Err(error) => principal_error(&error),
        }
    }

    async fn get(
        State(state): State<PrincipalRouteState>,
        Path(principal_id): Path<String>,
    ) -> Response {
        match state.handler.get(&principal_id).await {
            Ok(Some(principal)) => Json(principal).into_response(),
            Ok(None) => principal_error(&PrincipalHandlerError::NotFound(principal_id)),
            Err(error) => principal_error(&error),
        }
    }

    async fn update_status(
        State(state): State<PrincipalRouteState>,
        Path(principal_id): Path<String>,
        Json(update): Json<PrincipalStatusUpdate>,
    ) -> Response {
        state.handler.update_status(&principal_id, update.status).await.map_or_else(
            |error| principal_error(&error),
            |principal| Json(principal).into_response(),
        )
    }

    async fn delete(
        State(state): State<PrincipalRouteState>,
        Path(principal_id): Path<String>,
    ) -> Response {
        state.handler.delete(&principal_id).await.map_or_else(
            |error| principal_error(&error),
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
            .map_or_else(|error| principal_error(&error), |page| Json(page).into_response())
    }

    async fn materialize(
        State(state): State<PrincipalRouteState>,
        Json(request): Json<PrincipalMaterializationRequest>,
    ) -> Response {
        state.handler.materialize(&request).await.map_or_else(
            |error| principal_error(&error),
            |principal| (StatusCode::CREATED, Json(principal)).into_response(),
        )
    }
    const fn default_limit() -> u32 {
        20
    }
}
