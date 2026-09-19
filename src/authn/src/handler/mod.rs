pub mod authentication;
mod error;
pub(crate) mod oauth2;
pub(crate) mod standalone;
#[cfg(feature = "web3")]
pub(crate) mod wallet;
mod webauthn;

use authguard_common::model::AuthenticatedPrincipalContext;
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde::Serialize;

pub(crate) use authentication::{
    AuthenticationPipeline, AuthenticationPipelineError, AuthnRuntime, IssuedAuthentication,
};
pub(crate) use error::ApiError;
pub(crate) use oauth2::OAuth2Handler;
pub(crate) use standalone::StandaloneHandler;
#[cfg(feature = "web3")]
pub(crate) use wallet::WalletHandler;

pub(crate) const TOKEN_COOKIE: &str = "authguard_token";

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
    pub(crate) fn new(issued: IssuedAuthentication, return_uri: String) -> Self {
        Self {
            access_token: issued.access_token,
            token_type: "Bearer",
            expires_in: issued.expires_in,
            return_uri,
            principal: issued.principal,
        }
    }

    pub(crate) fn into_redirect(self) -> Result<Response, ApiError> {
        if self.return_uri.is_empty() {
            return Ok(self.into_response());
        }
        let mut response = Redirect::to(&self.return_uri).into_response();
        response.headers_mut().append(header::SET_COOKIE, self.session_cookie()?);
        response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        Ok(response)
    }

    fn session_cookie(&self) -> Result<HeaderValue, ApiError> {
        HeaderValue::from_str(&format!(
            "{TOKEN_COOKIE}={}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Lax",
            self.access_token, self.expires_in,
        ))
        .map_err(|_| ApiError::internal("canonical token could not be issued"))
    }
}

impl IntoResponse for LoginResponse {
    fn into_response(self) -> Response {
        let cookie = match self.session_cookie() {
            Ok(cookie) => cookie,
            Err(error) => return error.into_response(),
        };
        let mut response = Json(self).into_response();
        response.headers_mut().append(header::SET_COOKIE, cookie);
        response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}
