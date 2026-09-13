pub mod authentication;
mod error;

use authguard_common::model::AuthenticatedPrincipalContext;
use serde::Serialize;

pub(crate) use authentication::AuthenticationHandler;
pub(crate) use error::ApiError;

use crate::pipeline::AuthenticatedSession;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    return_uri: String,
    principal: AuthenticatedPrincipalContext,
}

impl LoginResponse {
    pub(crate) fn new(session: AuthenticatedSession, return_uri: String) -> Self {
        Self {
            access_token: session.access_token,
            token_type: "Bearer",
            expires_in: session.expires_in,
            return_uri,
            principal: session.principal,
        }
    }
}
