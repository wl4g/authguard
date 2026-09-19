use authguard_common::storage::CredentialRepositoryError;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::authentication::challenge::ChallengeError;
use crate::authentication::TokenError;
use crate::handler::AuthenticationPipelineError;

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

    #[cfg(feature = "web3")]
    pub(crate) const fn not_implemented(code: &'static str, message: &'static str) -> Self {
        Self { status: StatusCode::NOT_IMPLEMENTED, code, message }
    }

    pub(crate) const fn internal(message: &'static str) -> Self {
        Self { status: StatusCode::INTERNAL_SERVER_ERROR, code: "internal_error", message }
    }

    pub(crate) fn challenge(error: ChallengeError) -> Self {
        tracing::error!(error = %error, "authentication challenge operation failed");
        match error {
            ChallengeError::InvalidState => Self::bad_request("invalid or expired challenge"),
            ChallengeError::Backend => {
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
            AuthenticationPipelineError::Token(_) => {
                Self::internal("canonical token could not be issued")
            }
            AuthenticationPipelineError::StepUpPrincipalMismatch => Self {
                status: StatusCode::FORBIDDEN,
                code: "step_up_rejected",
                message: "step-up authentication does not match the current Principal",
            },
        }
    }

    pub(crate) fn token(error: TokenError) -> Self {
        tracing::warn!(error = %error, "canonical AuthGuard token rejected");
        match error {
            TokenError::InvalidToken => Self::unauthorized("valid AuthGuard token required"),
            TokenError::SigningUnavailable => {
                Self::internal("canonical token verification is unavailable")
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
            StatusCode::NOT_IMPLEMENTED => "unsupported",
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
