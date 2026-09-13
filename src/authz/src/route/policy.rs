//! Policy, action, role, and role-binding management routes.

#![allow(clippy::unused_async)] // Axum handlers must return futures.

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::handler::{AuthorizeRequest, PolicyHandler, PolicyHandlerError, ResourceItem};
use crate::model::{IamActionInfo, IamPolicyInfo, IamRoleBindingInfo, IamRoleInfo};

use super::ApiError;

#[derive(Clone)]
struct PolicyRouteState {
    handler: PolicyHandler,
}

// Implementation of PAP(Policy Administration Point)
pub struct PolicyRoutes {
    state: PolicyRouteState,
}

impl PolicyRoutes {
    #[must_use]
    pub fn new(handler: PolicyHandler) -> Self {
        Self { state: PolicyRouteState { handler } }
    }

    pub fn router(self) -> Router {
        Router::new()
            .route(
                "/api/v1/policy",
                get(Self::get_policy).put(Self::replace_policy).delete(Self::reset_policy),
            )
            .route("/api/v1/actions", get(Self::list_actions).post(Self::create_action))
            .route(
                "/api/v1/actions/{action_id}",
                get(Self::get_action).put(Self::update_action).delete(Self::delete_action),
            )
            .route("/api/v1/roles", get(Self::list_roles).post(Self::create_role))
            .route(
                "/api/v1/roles/{role_id}",
                get(Self::get_role).put(Self::update_role).delete(Self::delete_role),
            )
            .route(
                "/api/v1/role-bindings",
                get(Self::list_role_bindings).post(Self::create_role_binding),
            )
            .route(
                "/api/v1/role-bindings/{binding_id}",
                get(Self::get_role_binding)
                    .put(Self::update_role_binding)
                    .delete(Self::delete_role_binding),
            )
            .route("/api/v1/authorize", post(Self::authorize))
            .route("/api/v1/status", get(Self::status))
            .with_state(self.state)
    }

    async fn get_policy(State(state): State<PolicyRouteState>) -> Response {
        let policy = state.handler.catalog();
        let revision = policy.revision;
        Self::revisioned(Json(policy).into_response(), revision)
    }

    async fn replace_policy(
        State(state): State<PolicyRouteState>,
        headers: HeaderMap,
        Json(policy): Json<IamPolicyInfo>,
    ) -> Response {
        let expected = match Self::require_if_match(&headers) {
            Ok(expected) => expected,
            Err(error) => return error.into_response(),
        };
        match state.handler.replace(expected, policy).await {
            Ok(policy) => {
                let revision = policy.revision;
                Self::revisioned(Json(policy).into_response(), revision)
            }
            Err(error) => Self::handler_error(&error),
        }
    }

    async fn reset_policy(State(state): State<PolicyRouteState>, headers: HeaderMap) -> Response {
        let expected = match Self::require_if_match(&headers) {
            Ok(expected) => expected,
            Err(error) => return error.into_response(),
        };
        Self::deleted(state.handler.reset(expected).await)
    }

    async fn list_actions(State(state): State<PolicyRouteState>) -> Response {
        let actions = state.handler.actions();
        Self::revisioned(Json(&actions).into_response(), actions.policy_revision)
    }

    async fn create_action(
        State(state): State<PolicyRouteState>,
        headers: HeaderMap,
        Json(action): Json<IamActionInfo>,
    ) -> Response {
        let expected = match Self::require_if_match(&headers) {
            Ok(expected) => expected,
            Err(error) => return error.into_response(),
        };
        Self::created(state.handler.create_action(expected, action).await)
    }

    async fn get_action(
        State(state): State<PolicyRouteState>,
        Path(action_id): Path<String>,
    ) -> Response {
        Self::item(state.handler.action_item(&action_id))
    }

    async fn update_action(
        State(state): State<PolicyRouteState>,
        Path(action_id): Path<String>,
        headers: HeaderMap,
        Json(action): Json<IamActionInfo>,
    ) -> Response {
        let expected = match Self::require_if_match(&headers) {
            Ok(expected) => expected,
            Err(error) => return error.into_response(),
        };
        Self::updated(state.handler.update_action(expected, &action_id, action).await)
    }

    async fn delete_action(
        State(state): State<PolicyRouteState>,
        Path(action_id): Path<String>,
        headers: HeaderMap,
    ) -> Response {
        let expected = match Self::require_if_match(&headers) {
            Ok(expected) => expected,
            Err(error) => return error.into_response(),
        };
        Self::deleted(state.handler.delete_action(expected, &action_id).await)
    }

    async fn list_roles(State(state): State<PolicyRouteState>) -> Response {
        let roles = state.handler.roles();
        Self::revisioned(Json(&roles).into_response(), roles.policy_revision)
    }

    async fn create_role(
        State(state): State<PolicyRouteState>,
        headers: HeaderMap,
        Json(role): Json<IamRoleInfo>,
    ) -> Response {
        let expected = match Self::require_if_match(&headers) {
            Ok(expected) => expected,
            Err(error) => return error.into_response(),
        };
        Self::created(state.handler.create_role(expected, role).await)
    }

    async fn get_role(
        State(state): State<PolicyRouteState>,
        Path(role_id): Path<String>,
    ) -> Response {
        Self::item(state.handler.role_item(&role_id))
    }

    async fn update_role(
        State(state): State<PolicyRouteState>,
        Path(role_id): Path<String>,
        headers: HeaderMap,
        Json(role): Json<IamRoleInfo>,
    ) -> Response {
        let expected = match Self::require_if_match(&headers) {
            Ok(expected) => expected,
            Err(error) => return error.into_response(),
        };
        Self::updated(state.handler.update_role(expected, &role_id, role).await)
    }

    async fn delete_role(
        State(state): State<PolicyRouteState>,
        Path(role_id): Path<String>,
        headers: HeaderMap,
    ) -> Response {
        let expected = match Self::require_if_match(&headers) {
            Ok(expected) => expected,
            Err(error) => return error.into_response(),
        };
        Self::deleted(state.handler.delete_role(expected, &role_id).await)
    }

    async fn list_role_bindings(State(state): State<PolicyRouteState>) -> Response {
        let bindings = state.handler.role_bindings();
        Self::revisioned(Json(&bindings).into_response(), bindings.policy_revision)
    }

    async fn create_role_binding(
        State(state): State<PolicyRouteState>,
        headers: HeaderMap,
        Json(binding): Json<IamRoleBindingInfo>,
    ) -> Response {
        let expected = match Self::require_if_match(&headers) {
            Ok(expected) => expected,
            Err(error) => return error.into_response(),
        };
        Self::created(state.handler.create_role_binding(expected, binding).await)
    }

    async fn get_role_binding(
        State(state): State<PolicyRouteState>,
        Path(binding_id): Path<String>,
    ) -> Response {
        Self::item(state.handler.role_binding_item(&binding_id))
    }

    async fn update_role_binding(
        State(state): State<PolicyRouteState>,
        Path(binding_id): Path<String>,
        headers: HeaderMap,
        Json(binding): Json<IamRoleBindingInfo>,
    ) -> Response {
        let expected = match Self::require_if_match(&headers) {
            Ok(expected) => expected,
            Err(error) => return error.into_response(),
        };
        Self::updated(state.handler.update_role_binding(expected, &binding_id, binding).await)
    }

    async fn delete_role_binding(
        State(state): State<PolicyRouteState>,
        Path(binding_id): Path<String>,
        headers: HeaderMap,
    ) -> Response {
        let expected = match Self::require_if_match(&headers) {
            Ok(expected) => expected,
            Err(error) => return error.into_response(),
        };
        Self::deleted(state.handler.delete_role_binding(expected, &binding_id).await)
    }

    async fn authorize(
        State(state): State<PolicyRouteState>,
        Json(request): Json<AuthorizeRequest>,
    ) -> Response {
        match state.handler.authorize_request(request).await {
            Ok(decision) => {
                let status = if decision.allowed { StatusCode::OK } else { StatusCode::FORBIDDEN };
                (status, Json(decision)).into_response()
            }
            Err(error) => Self::handler_error(&error),
        }
    }

    async fn status(State(state): State<PolicyRouteState>) -> Response {
        let status = state.handler.status();
        Self::revisioned(Json(&status).into_response(), status.policy_revision)
    }
}

impl PolicyRoutes {
    fn parse_if_match(headers: &HeaderMap) -> Result<Option<u64>, ()> {
        let Some(value) = headers.get("if-match") else {
            return Ok(None);
        };
        let value = value.to_str().map_err(|_| ())?.trim_matches('"');
        value.parse().map(Some).map_err(|_| ())
    }
}

#[derive(Clone, Copy)]
enum IfMatchError {
    Missing,
    Invalid,
}

impl IfMatchError {
    fn into_response(self) -> Response {
        match self {
            Self::Missing => (
                StatusCode::PRECONDITION_REQUIRED,
                Json(ApiError::new(
                    "if_match_required",
                    "If-Match with the current policy ETag is required",
                )),
            )
                .into_response(),
            Self::Invalid => (
                StatusCode::BAD_REQUEST,
                Json(ApiError::new(
                    "invalid_if_match",
                    "If-Match must contain one policy revision",
                )),
            )
                .into_response(),
        }
    }
}

impl PolicyRoutes {
    fn require_if_match(headers: &HeaderMap) -> Result<u64, IfMatchError> {
        match Self::parse_if_match(headers) {
            Ok(Some(revision)) => Ok(revision),
            Ok(None) => Err(IfMatchError::Missing),
            Err(()) => Err(IfMatchError::Invalid),
        }
    }

    fn item<T: serde::Serialize>(result: Result<ResourceItem<T>, PolicyHandlerError>) -> Response {
        result.map_or_else(
            |error| Self::handler_error(&error),
            |item| {
                let revision = item.policy_revision;
                Self::revisioned(Json(item).into_response(), revision)
            },
        )
    }

    fn created<T: serde::Serialize>(result: Result<(u64, T), PolicyHandlerError>) -> Response {
        result.map_or_else(
            |error| Self::handler_error(&error),
            |(policy_revision, resource)| {
                Self::revisioned(
                    (StatusCode::CREATED, Json(ResourceItem { policy_revision, resource }))
                        .into_response(),
                    policy_revision,
                )
            },
        )
    }

    fn updated<T: serde::Serialize>(result: Result<(u64, T), PolicyHandlerError>) -> Response {
        result.map_or_else(
            |error| Self::handler_error(&error),
            |(policy_revision, resource)| {
                Self::revisioned(
                    Json(ResourceItem { policy_revision, resource }).into_response(),
                    policy_revision,
                )
            },
        )
    }

    fn deleted(result: Result<u64, PolicyHandlerError>) -> Response {
        result.map_or_else(
            |error| Self::handler_error(&error),
            |revision| {
                let response = StatusCode::NO_CONTENT.into_response();
                Self::revisioned(response, revision)
            },
        )
    }

    fn handler_error(error: &PolicyHandlerError) -> Response {
        let (status, code) = match error {
            PolicyHandlerError::AlreadyExists { .. } => {
                (StatusCode::CONFLICT, "resource_already_exists")
            }
            PolicyHandlerError::NotFound { .. } => (StatusCode::NOT_FOUND, "resource_not_found"),
            PolicyHandlerError::IdMismatch { .. } => {
                (StatusCode::BAD_REQUEST, "resource_id_mismatch")
            }
            PolicyHandlerError::PrincipalDisabled(_) => {
                (StatusCode::CONFLICT, "principal_disabled")
            }
            PolicyHandlerError::Referenced { .. } => {
                (StatusCode::CONFLICT, "resource_still_referenced")
            }
            PolicyHandlerError::RevisionConflict { .. } => {
                (StatusCode::PRECONDITION_FAILED, "policy_revision_conflict")
            }
            PolicyHandlerError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            PolicyHandlerError::AuthorizationPrincipalInactive(_) => {
                (StatusCode::FORBIDDEN, "principal_not_active")
            }
            PolicyHandlerError::InvalidPolicy(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "invalid_policy")
            }
            PolicyHandlerError::Storage(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, "policy_storage_unavailable")
            }
        };
        if matches!(error, PolicyHandlerError::Storage(_)) {
            tracing::error!(
                authguard.policy.error_code = code,
                %error,
                "policy operation failed because storage is unavailable"
            );
        } else {
            tracing::warn!(
                authguard.policy.error_code = code,
                %error,
                "policy operation rejected"
            );
        }
        (status, Json(ApiError::new(code, error.to_string()))).into_response()
    }

    fn revisioned(mut response: Response, revision: u64) -> Response {
        response.headers_mut().insert(
            header::ETAG,
            HeaderValue::from_str(&format!("\"{revision}\""))
                .expect("u64 policy revision is a valid strong ETag"),
        );
        response.headers_mut().insert(
            "x-authguard-policy-revision",
            HeaderValue::from_str(&revision.to_string())
                .expect("u64 policy revision is a valid header value"),
        );
        response
    }
}
