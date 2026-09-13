use authguard_common::storage::CredentialRepositoryError;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::challenge::ChallengeStoreError;
use crate::pipeline::AuthenticationPipelineError;
use crate::session::SessionError;

#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    pub(crate) code: &'static str,
    message: &'static str,
}

impl ApiError {
    pub(crate) const fn bad_request(message: &'static str) -> Self {
        Self { status: StatusCode::BAD_REQUEST, code: "invalid_request", message }
    }

    pub(crate) const fn unauthorized(message: &'static str) -> Self {
        Self { status: StatusCode::UNAUTHORIZED, code: "authentication_failed", message }
    }

    pub(crate) const fn not_found(message: &'static str) -> Self {
        Self { status: StatusCode::NOT_FOUND, code: "not_found", message }
    }

    pub(crate) const fn conflict(message: &'static str) -> Self {
        Self { status: StatusCode::CONFLICT, code: "conflict", message }
    }

    pub(crate) const fn unavailable(message: &'static str) -> Self {
        Self { status: StatusCode::SERVICE_UNAVAILABLE, code: "service_unavailable", message }
    }

    pub(crate) const fn internal(message: &'static str) -> Self {
        Self { status: StatusCode::INTERNAL_SERVER_ERROR, code: "internal_error", message }
    }

    pub(crate) fn challenge(error: ChallengeStoreError) -> Self {
        tracing::error!(error = %error, "authentication challenge operation failed");
        match error {
            ChallengeStoreError::InvalidState => Self::bad_request("invalid or expired challenge"),
            ChallengeStoreError::Backend => {
                Self::unavailable("authentication challenge service is unavailable")
            }
        }
    }

    pub(crate) fn pipeline(error: AuthenticationPipelineError) -> Self {
        tracing::warn!(error = %error, "authentication convergence failed closed");
        match error {
            AuthenticationPipelineError::Linking(linking) => match linking {
                crate::AccountLinkingError::AuthoritativeLoginRequired { .. }
                | crate::AccountLinkingError::LinkNotAllowed { .. }
                | crate::AccountLinkingError::PrincipalDisabled(_) => Self {
                    status: StatusCode::FORBIDDEN,
                    code: "account_linking_rejected",
                    message: "account linking was rejected",
                },
                crate::AccountLinkingError::IdentityAlreadyBound => {
                    Self::conflict("external identity is already linked")
                }
                _ => Self::unavailable("account linking is unavailable"),
            },
            AuthenticationPipelineError::Session(_) => {
                Self::internal("canonical session token could not be issued")
            }
        }
    }

    pub(crate) fn session(error: SessionError) -> Self {
        tracing::warn!(error = %error, "canonical AuthGuard session rejected");
        match error {
            SessionError::InvalidToken => Self::unauthorized("valid AuthGuard session required"),
            SessionError::SigningUnavailable => {
                Self::internal("canonical session verification is unavailable")
            }
        }
    }

    pub(crate) fn credential(error: CredentialRepositoryError) -> Self {
        tracing::error!(error = %error, "standalone credential storage failed");
        let response = match &error {
            CredentialRepositoryError::KeyConflict => {
                Self::conflict("credential identifier is already registered")
            }
            CredentialRepositoryError::Backend(_) => {
                Self::unavailable("credential storage is unavailable")
            }
        };
        drop(error);
        response
    }

    pub(crate) fn metric_outcome(&self) -> &'static str {
        match self.status {
            StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND => "invalid_request",
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => "rejected",
            StatusCode::CONFLICT => "conflict",
            StatusCode::SERVICE_UNAVAILABLE => "unavailable",
            _ => "error",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"code": self.code, "message": self.message}))).into_response()
    }
}
