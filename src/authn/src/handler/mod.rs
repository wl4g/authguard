pub mod authentication;
mod error;
pub(crate) mod oauth2;
pub(crate) mod standalone;
#[cfg(feature = "web3")]
pub(crate) mod wallet;
mod webauthn;

use authguard_common::model::AuthenticatedPrincipalContext;
use serde::Serialize;

pub(crate) use authentication::{
    AuthenticationPipeline, AuthenticationPipelineError, AuthnRuntime, IssuedAuthentication,
};
pub(crate) use error::ApiError;
pub(crate) use oauth2::OAuth2Handler;
pub(crate) use standalone::StandaloneHandler;
#[cfg(feature = "web3")]
pub(crate) use wallet::WalletHandler;

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
}
