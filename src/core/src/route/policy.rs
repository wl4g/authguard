#![allow(clippy::unused_async)] // Axum handlers must return futures.

use std::str::FromStr;
use std::time::Instant;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::handler::{PolicyHandler, PolicyHandlerError, PrincipalHandler};
use crate::model::{Action, AuthorizationRequest, Policy, ResourceUrn, Role, RoleBinding};
use crate::model::{
    ApiError, AuthorizePayload, AuthorizeResponse, ResourceCollectionResponse, ResourceResponse,
    StatusResponse,
};
use crate::utils::MetricsRegistry;

#[derive(Clone)]
struct PolicyRouteState {
    handler: PolicyHandler,
    principals: PrincipalHandler,
    metrics: MetricsRegistry,
}

pub struct PolicyRoutes {
    state: PolicyRouteState,
}

impl PolicyRoutes {
    #[must_use]
    pub fn new(
        handler: PolicyHandler,
        principals: PrincipalHandler,
        metrics: MetricsRegistry,
    ) -> Self {
        Self { state: PolicyRouteState { handler, principals, metrics } }
    }

    pub fn router(self) -> Router {
        Router::new()
            .route(
                "/adm/v1/policy",
                get(Self::get_policy).put(Self::replace_policy).delete(Self::reset_policy),
            )
            .route("/adm/v1/actions", get(Self::list_actions).post(Self::create_action))
            .route(
                "/adm/v1/actions/{action_id}",
                get(Self::get_action).put(Self::update_action).delete(Self::delete_action),
            )
            .route("/adm/v1/roles", get(Self::list_roles).post(Self::create_role))
            .route(
                "/adm/v1/roles/{role_id}",
                get(Self::get_role).put(Self::update_role).delete(Self::delete_role),
            )
            .route(
                "/adm/v1/role-bindings",
                get(Self::list_role_bindings).post(Self::create_role_binding),
            )
            .route(
                "/adm/v1/role-bindings/{binding_id}",
                get(Self::get_role_binding)
                    .put(Self::update_role_binding)
                    .delete(Self::delete_role_binding),
            )
            .route("/adm/v1/authorize", post(Self::authorize))
            .route("/adm/v1/status", get(Self::status))
            .with_state(self.state)
    }

    async fn get_policy(State(state): State<PolicyRouteState>) -> Response {
        let policy = state.handler.snapshot();
        let revision = policy.revision;
        Self::revisioned(Json(policy).into_response(), revision)
    }

    async fn replace_policy(
        State(state): State<PolicyRouteState>,
        headers: HeaderMap,
        Json(policy): Json<Policy>,
    ) -> Response {
        let expected = match Self::require_if_match(&headers) {
            Ok(expected) => expected,
            Err(error) => return error.into_response(),
        };
        if expected != policy.revision {
            return Self::bad_request(
                "policy_revision_mismatch",
                "If-Match must equal the policy revision in the request body",
            );
        }
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
        let policy = state.handler.snapshot();
        let revision = policy.revision;
        Self::revisioned(
            Json(ResourceCollectionResponse {
                policy_revision: revision,
                total: policy.actions.len(),
                items: policy.actions,
            })
            .into_response(),
            revision,
        )
    }

    async fn create_action(
        State(state): State<PolicyRouteState>,
        headers: HeaderMap,
        Json(action): Json<Action>,
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
        let policy = state.handler.snapshot();
        let action = policy.actions.iter().find(|action| action.identifier == action_id).cloned();
        Self::resource(policy.revision, action, "action", &action_id)
    }

    async fn update_action(
        State(state): State<PolicyRouteState>,
        Path(action_id): Path<String>,
        headers: HeaderMap,
        Json(action): Json<Action>,
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
        let policy = state.handler.snapshot();
        let revision = policy.revision;
        Self::revisioned(
            Json(ResourceCollectionResponse {
                policy_revision: revision,
                total: policy.roles.len(),
                items: policy.roles,
            })
            .into_response(),
            revision,
        )
    }

    async fn create_role(
        State(state): State<PolicyRouteState>,
        headers: HeaderMap,
        Json(role): Json<Role>,
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
        let policy = state.handler.snapshot();
        let role = policy.roles.iter().find(|role| role.id == role_id).cloned();
        Self::resource(policy.revision, role, "role", &role_id)
    }

    async fn update_role(
        State(state): State<PolicyRouteState>,
        Path(role_id): Path<String>,
        headers: HeaderMap,
        Json(role): Json<Role>,
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
        let policy = state.handler.snapshot();
        let revision = policy.revision;
        Self::revisioned(
            Json(ResourceCollectionResponse {
                policy_revision: revision,
                total: policy.role_bindings.len(),
                items: policy.role_bindings,
            })
            .into_response(),
            revision,
        )
    }

    async fn create_role_binding(
        State(state): State<PolicyRouteState>,
        headers: HeaderMap,
        Json(binding): Json<RoleBinding>,
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
        let policy = state.handler.snapshot();
        let binding = policy.role_bindings.iter().find(|binding| binding.id == binding_id).cloned();
        Self::resource(policy.revision, binding, "role binding", &binding_id)
    }

    async fn update_role_binding(
        State(state): State<PolicyRouteState>,
        Path(binding_id): Path<String>,
        headers: HeaderMap,
        Json(binding): Json<RoleBinding>,
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
        Json(payload): Json<AuthorizePayload>,
    ) -> Response {
        let started = Instant::now();
        if payload.principal_id.trim().is_empty()
            || payload.action.trim().is_empty()
            || payload.resource_urn.trim().is_empty()
        {
            return Self::bad_request(
                "invalid_request",
                "principal_id, action, and resource_urn are required",
            );
        }
        let resource_urn = match ResourceUrn::from_str(&payload.resource_urn) {
            Ok(urn) => urn,
            Err(error) => return Self::bad_request("invalid_resource_urn", error.to_string()),
        };
        let parent_urns = match payload
            .parent_urns
            .iter()
            .map(|urn| ResourceUrn::from_str(urn))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(urns) => urns,
            Err(error) => return Self::bad_request("invalid_parent_urn", error.to_string()),
        };
        match state.principals.get(&payload.principal_id).await {
            Ok(Some(principal)) if principal.status == crate::model::PrincipalStatus::Active => {}
            Ok(_) => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(ApiError::new(
                        "principal_not_active",
                        "authorization requires an active projected principal",
                    )),
                )
                    .into_response()
            }
            Err(error) => {
                tracing::error!(%error, "failed to validate principal for admin authorization");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ApiError::new(
                        "principal_storage_unavailable",
                        "principal storage is temporarily unavailable",
                    )),
                )
                    .into_response();
            }
        }
        let authorization_request = AuthorizationRequest {
            principal_id: payload.principal_id,
            group_principal_ids: payload.group_principal_ids,
            action: payload.action,
            resource_urn,
            parent_urns,
            context: payload.context,
        };
        let decision = state.handler.authorize(&authorization_request);
        state.metrics.record_authorization(
            decision.allowed,
            &decision.reason,
            started.elapsed().as_secs_f64(),
        );
        tracing::info!(
            authguard.decision = if decision.allowed { "allow" } else { "deny" },
            authguard.reason = %decision.reason,
            authguard.principal_id = %authorization_request.principal_id,
            authguard.principal_group_count = authorization_request.group_principal_ids.len(),
            authguard.action = %authorization_request.action,
            authguard.resource_service = %authorization_request.resource_urn.service,
            authguard.role_binding_id = decision.role_binding_id.as_deref().unwrap_or("none"),
            duration_seconds = started.elapsed().as_secs_f64(),
            "control-plane authorization evaluation completed"
        );
        let status = if decision.allowed { StatusCode::OK } else { StatusCode::FORBIDDEN };
        (
            status,
            Json(AuthorizeResponse {
                allowed: decision.allowed,
                reason: decision.reason,
                role_binding_id: decision.role_binding_id,
            }),
        )
            .into_response()
    }

    async fn status(State(state): State<PolicyRouteState>) -> Response {
        let policy = state.handler.snapshot();
        let revision = policy.revision;
        Self::revisioned(
            Json(StatusResponse {
                status: "ok".to_string(),
                policy_revision: revision,
                actions: policy.actions.len(),
                roles: policy.roles.len(),
                role_bindings: policy.role_bindings.len(),
                route_matchers: policy
                    .actions
                    .iter()
                    .map(|action| action.route_matchers.len())
                    .sum(),
            })
            .into_response(),
            revision,
        )
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
            Self::Invalid => PolicyRoutes::bad_request(
                "invalid_if_match",
                "If-Match must contain one policy revision",
            ),
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

    fn resource<T: serde::Serialize>(
        policy_revision: u64,
        value: Option<T>,
        kind: &'static str,
        id: &str,
    ) -> Response {
        value.map_or_else(
            || {
                Self::handler_error(&PolicyHandlerError::NotFound {
                    resource: kind,
                    id: id.to_string(),
                })
            },
            |resource| {
                Self::revisioned(
                    Json(ResourceResponse { policy_revision, resource }).into_response(),
                    policy_revision,
                )
            },
        )
    }

    fn created<T: serde::Serialize>(result: Result<(u64, T), PolicyHandlerError>) -> Response {
        result.map_or_else(
            |error| Self::handler_error(&error),
            |(policy_revision, resource)| {
                Self::revisioned(
                    (StatusCode::CREATED, Json(ResourceResponse { policy_revision, resource }))
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
                    Json(ResourceResponse { policy_revision, resource }).into_response(),
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

    fn bad_request(code: &'static str, message: impl Into<String>) -> Response {
        (StatusCode::BAD_REQUEST, Json(ApiError::new(code, message))).into_response()
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
