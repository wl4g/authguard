//! SCIM 2.0 User and Group provisioning endpoints.
//!
//! Protocol references:
//! - RFC 7644 resource endpoints: <https://www.rfc-editor.org/rfc/rfc7644.html#section-3.2>
//! - RFC 7644 create/retrieve/replace/PATCH/delete:
//!   <https://www.rfc-editor.org/rfc/rfc7644.html#section-3.3>
//!   <https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4>
//!   <https://www.rfc-editor.org/rfc/rfc7644.html#section-3.5>
//!   <https://www.rfc-editor.org/rfc/rfc7644.html#section-3.6>
//! - RFC 7643 User and Group schemas:
//!   <https://www.rfc-editor.org/rfc/rfc7643.html#section-4.1>
//!   <https://www.rfc-editor.org/rfc/rfc7643.html#section-4.2>
//! - GitHub Enterprise SCIM integration:
//!   <https://docs.github.com/en/enterprise-cloud@latest/rest/authentication/permissions-required-for-github-apps?apiVersion=2026-03-10#enterprise-permissions-for-enterprise-scim>
//!
//! `AuthGuard` implements a bounded profile. Unsupported complex filters and
//! PATCH paths return SCIM errors instead of being silently accepted.

#![allow(clippy::unused_async)] // Axum handlers must return futures.

use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_TYPE, LOCATION};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::handler::{PrincipalHandler, PrincipalHandlerError};
use crate::model::PrincipalKind;
use crate::principal::{
    PrincipalDiscoveryError, ScimErrorResponse, ScimGroupResource, ScimListQuery, ScimPatchRequest,
    ScimResource, ScimUserResource, ERROR_SCHEMA,
};

pub struct ScimRoutes {
    handler: PrincipalHandler,
}

impl ScimRoutes {
    #[must_use]
    pub fn new(handler: PrincipalHandler) -> Self {
        Self { handler }
    }

    pub fn router(self) -> Router {
        Router::new()
            .route("/scim/v2/Users", get(Self::list_users).post(Self::create_user))
            .route(
                "/scim/v2/Users/{id}",
                get(Self::get_user)
                    .put(Self::replace_user)
                    .patch(Self::patch_user)
                    .delete(Self::delete_user),
            )
            .route("/scim/v2/Groups", get(Self::list_groups).post(Self::create_group))
            .route(
                "/scim/v2/Groups/{id}",
                get(Self::get_group)
                    .put(Self::replace_group)
                    .patch(Self::patch_group)
                    .delete(Self::delete_group),
            )
            .with_state(self.handler)
    }

    async fn create_user(
        State(handler): State<PrincipalHandler>,
        Json(resource): Json<ScimUserResource>,
    ) -> Response {
        Self::upsert(&handler, String::new(), ScimResource::User(resource), false).await
    }

    async fn replace_user(
        State(handler): State<PrincipalHandler>,
        Path(id): Path<String>,
        Json(resource): Json<ScimUserResource>,
    ) -> Response {
        Self::upsert(&handler, id, ScimResource::User(resource), true).await
    }

    async fn get_user(State(handler): State<PrincipalHandler>, Path(id): Path<String>) -> Response {
        Self::get(&handler, &id, PrincipalKind::User).await
    }

    async fn list_users(
        State(handler): State<PrincipalHandler>,
        Query(query): Query<ScimListQuery>,
    ) -> Response {
        Self::list(&handler, PrincipalKind::User, &query).await
    }

    async fn patch_user(
        State(handler): State<PrincipalHandler>,
        Path(id): Path<String>,
        Json(patch): Json<ScimPatchRequest>,
    ) -> Response {
        Self::patch(&handler, &id, PrincipalKind::User, &patch).await
    }

    async fn delete_user(
        State(handler): State<PrincipalHandler>,
        Path(id): Path<String>,
    ) -> Response {
        Self::delete(&handler, &id, PrincipalKind::User).await
    }

    async fn create_group(
        State(handler): State<PrincipalHandler>,
        Json(resource): Json<ScimGroupResource>,
    ) -> Response {
        Self::upsert(&handler, String::new(), ScimResource::Group(resource), false).await
    }

    async fn replace_group(
        State(handler): State<PrincipalHandler>,
        Path(id): Path<String>,
        Json(resource): Json<ScimGroupResource>,
    ) -> Response {
        Self::upsert(&handler, id, ScimResource::Group(resource), true).await
    }

    async fn get_group(
        State(handler): State<PrincipalHandler>,
        Path(id): Path<String>,
    ) -> Response {
        Self::get(&handler, &id, PrincipalKind::Group).await
    }

    async fn list_groups(
        State(handler): State<PrincipalHandler>,
        Query(query): Query<ScimListQuery>,
    ) -> Response {
        Self::list(&handler, PrincipalKind::Group, &query).await
    }

    async fn patch_group(
        State(handler): State<PrincipalHandler>,
        Path(id): Path<String>,
        Json(patch): Json<ScimPatchRequest>,
    ) -> Response {
        Self::patch(&handler, &id, PrincipalKind::Group, &patch).await
    }

    async fn delete_group(
        State(handler): State<PrincipalHandler>,
        Path(id): Path<String>,
    ) -> Response {
        Self::delete(&handler, &id, PrincipalKind::Group).await
    }

    async fn upsert(
        handler: &PrincipalHandler,
        principal_id: String,
        resource: ScimResource,
        replace: bool,
    ) -> Response {
        match handler.upsert_scim(principal_id, resource, replace).await {
            Ok(resource) => {
                let status = if replace { StatusCode::OK } else { StatusCode::CREATED };
                let location = resource.location();
                resource_response(status, &resource, location)
            }
            Err(error) => handler_error(&error),
        }
    }

    async fn get(handler: &PrincipalHandler, principal_id: &str, kind: PrincipalKind) -> Response {
        match handler.get_scim(principal_id, kind).await {
            Ok(resource) => resource_response(StatusCode::OK, &resource, None),
            Err(error) => handler_error(&error),
        }
    }

    async fn list(
        handler: &PrincipalHandler,
        kind: PrincipalKind,
        query: &ScimListQuery,
    ) -> Response {
        match handler.list_scim(kind, query).await {
            Ok(response) => scim_json(StatusCode::OK, &response, None),
            Err(error) => handler_error(&error),
        }
    }

    async fn patch(
        handler: &PrincipalHandler,
        principal_id: &str,
        kind: PrincipalKind,
        patch: &ScimPatchRequest,
    ) -> Response {
        match handler.patch_scim(principal_id, kind, patch).await {
            Ok(resource) => resource_response(StatusCode::OK, &resource, None),
            Err(error) => handler_error(&error),
        }
    }

    async fn delete(
        handler: &PrincipalHandler,
        principal_id: &str,
        kind: PrincipalKind,
    ) -> Response {
        match handler.delete_scim(principal_id, kind).await {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(error) => handler_error(&error),
        }
    }
}

fn handler_error(error: &PrincipalHandlerError) -> Response {
    let (status, scim_type) = match error {
        PrincipalHandlerError::NotFound(_) => (StatusCode::NOT_FOUND, "notFound"),
        PrincipalHandlerError::IdentityConflict => (StatusCode::CONFLICT, "uniqueness"),
        PrincipalHandlerError::Discovery(PrincipalDiscoveryError::InvalidQuery(message))
            if message.starts_with("SCIM filter") =>
        {
            (StatusCode::BAD_REQUEST, "invalidFilter")
        }
        PrincipalHandlerError::Discovery(_) => (StatusCode::BAD_REQUEST, "invalidValue"),
        PrincipalHandlerError::KindMismatch(_)
        | PrincipalHandlerError::Disabled(_)
        | PrincipalHandlerError::Referenced(_) => (StatusCode::CONFLICT, "mutability"),
        PrincipalHandlerError::ProviderUnavailable | PrincipalHandlerError::Storage(_) => {
            tracing::error!(%error, "SCIM provisioning failed");
            (StatusCode::SERVICE_UNAVAILABLE, "temporarilyUnavailable")
        }
    };
    scim_error(status, scim_type, &error.to_string())
}

fn resource_response(
    status: StatusCode,
    resource: &ScimResource,
    location: Option<&str>,
) -> Response {
    match resource {
        ScimResource::User(resource) => scim_json(status, resource, location),
        ScimResource::Group(resource) => scim_json(status, resource, location),
    }
}

fn scim_json<T: Serialize>(status: StatusCode, body: &T, location: Option<&str>) -> Response {
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/scim+json"));
    if let Some(location) = location.and_then(|value| HeaderValue::from_str(value).ok()) {
        response.headers_mut().insert(LOCATION, location);
    }
    response
}

fn scim_error(status: StatusCode, scim_type: &str, detail: &str) -> Response {
    scim_json(
        status,
        &ScimErrorResponse {
            schemas: vec![ERROR_SCHEMA.to_string()],
            status: status.as_u16().to_string(),
            scim_type: Some(scim_type.to_string()),
            detail: detail.to_string(),
        },
        None,
    )
}
