//! `WebAuthn` ceremony adapter. Cryptography and RP/origin validation are
//! delegated to the audited `webauthn-rs` implementation.

use authguard_common::model::{
    AuthenticationResult as DomainAuthenticationResult, ExternalIdentity, IamStandaloneCredential,
    PrincipalKind, StandaloneCredentialKind,
};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{
    CreationChallengeResponse, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse,
};

use super::standalone::{normalize_login, LoginRequest, StandaloneHandler};
use crate::authentication::challenge::{consume_json, put_json};
use crate::authentication::random_id;
use crate::handler::{ApiError, LoginResponse};
use crate::provider::standalone::WebauthnProviderError;

const REGISTRATION_PURPOSE: &str = "standalone-webauthn-registration";
const AUTHENTICATION_PURPOSE: &str = "standalone-webauthn-authentication";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RegistrationChallengeRequest {
    login: String,
    password: String,
    totp: Option<String>,
    display_name: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegistrationChallengeResponse {
    challenge_id: String,
    options: CreationChallengeResponse,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RegistrationVerifyRequest {
    challenge_id: String,
    credential: RegisterPublicKeyCredential,
    #[serde(default)]
    return_to: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AuthenticationChallengeRequest {
    login: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthenticationChallengeResponse {
    challenge_id: String,
    options: RequestChallengeResponse,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AuthenticationVerifyRequest {
    challenge_id: String,
    credential: PublicKeyCredential,
    #[serde(default)]
    return_to: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationChallenge {
    principal_id: String,
    external_identity: ExternalIdentity,
    amr: Vec<String>,
    state: PasskeyRegistration,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticationChallenge {
    external_identity: ExternalIdentity,
    state: PasskeyAuthentication,
}

pub(crate) async fn webauthn_registration_challenge(
    State(handler): State<StandaloneHandler>,
    headers: HeaderMap,
    Json(request): Json<RegistrationChallengeRequest>,
) -> Result<Json<RegistrationChallengeResponse>, ApiError> {
    let webauthn =
        handler.webauthn.as_ref().ok_or_else(|| ApiError::not_found("WebAuthn is not enabled"))?;
    let principal_id =
        handler.pipeline.authenticate_request_principal(&headers).map_err(ApiError::token)?;
    let authentication = handler
        .authenticate_credentials(LoginRequest {
            login: request.login,
            password: request.password,
            totp: request.totp,
            return_to: String::new(),
        })
        .await?;
    handler
        .pipeline
        .verify_step_up(&principal_id, &authentication, PrincipalKind::User)
        .await
        .map_err(ApiError::pipeline)?;
    let identity_key = authentication
        .external_identity
        .key()
        .map_err(|_| ApiError::internal("standalone identity is invalid"))?;
    let existing = handler
        .credentials
        .list_by_identity(&identity_key, StandaloneCredentialKind::Webauthn)
        .await
        .map_err(ApiError::credential)?;
    let display_name = request
        .display_name
        .or_else(|| {
            authentication
                .external_identity
                .claims
                .get("display_name")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "AuthGuard user".to_string());
    let (options, registration) = webauthn
        .start_registration(&identity_key, &display_name, &existing)
        .map_err(webauthn_error)?;
    let challenge_id = random_id();
    put_json(
        handler.challenge_store()?,
        REGISTRATION_PURPOSE,
        &challenge_id,
        &RegistrationChallenge {
            principal_id,
            external_identity: authentication.external_identity,
            amr: authentication.amr,
            state: registration,
        },
        handler.challenge_ttl,
    )
    .await
    .map_err(ApiError::challenge)?;
    Ok(Json(RegistrationChallengeResponse { challenge_id, options }))
}

pub(crate) async fn webauthn_registration_verify(
    State(handler): State<StandaloneHandler>,
    headers: HeaderMap,
    Json(request): Json<RegistrationVerifyRequest>,
) -> Result<LoginResponse, ApiError> {
    let return_to = crate::route::application::ApplicationResolver::new(
        authguard_common::config::AppConfig::get().get_authn(),
        &headers,
    )
    .validate_return_to(&request.return_to)?;
    let webauthn =
        handler.webauthn.as_ref().ok_or_else(|| ApiError::not_found("WebAuthn is not enabled"))?;
    let principal_id =
        handler.pipeline.authenticate_request_principal(&headers).map_err(ApiError::token)?;
    let challenge = consume_json::<RegistrationChallenge>(
        handler.challenge_store()?,
        REGISTRATION_PURPOSE,
        &request.challenge_id,
    )
    .await
    .map_err(ApiError::challenge)?
    .ok_or_else(|| ApiError::bad_request("invalid or expired WebAuthn challenge"))?;
    if challenge.principal_id != principal_id {
        return Err(ApiError::unauthorized("WebAuthn registration belongs to another Principal"));
    }
    let (credential_key, credential_data) = webauthn
        .finish_registration(&request.credential, &challenge.state)
        .map_err(webauthn_error)?;
    let identity = challenge
        .external_identity
        .key()
        .map_err(|_| ApiError::bad_request("invalid standalone identity"))?;
    let authentication = DomainAuthenticationResult::new(
        challenge.external_identity,
        challenge.amr.into_iter().chain(["webauthn".to_string()]),
        Some("urn:authguard:acr:webauthn:uv".to_string()),
        Utc::now(),
    );
    let issued = handler
        .pipeline
        .complete_step_up(&principal_id, authentication, PrincipalKind::User)
        .await
        .map_err(ApiError::pipeline)?;
    // Resolve the fresh step-up proof to the current Principal before making
    // the credential durable. A concurrent identity ownership change must not
    // leave an orphaned passkey behind.
    handler
        .credentials
        .create_credential(&IamStandaloneCredential {
            id: format!("webauthn_{}", random_id()),
            identity,
            kind: StandaloneCredentialKind::Webauthn,
            credential_key: Some(credential_key),
            secret_data: None,
            credential_data: Some(credential_data),
        })
        .await
        .map_err(ApiError::credential)?;
    Ok(LoginResponse::new(issued, return_to))
}

pub(crate) async fn webauthn_authentication_challenge(
    State(handler): State<StandaloneHandler>,
    Json(request): Json<AuthenticationChallengeRequest>,
) -> Result<Json<AuthenticationChallengeResponse>, ApiError> {
    let webauthn =
        handler.webauthn.as_ref().ok_or_else(|| ApiError::not_found("WebAuthn is not enabled"))?;
    let login = normalize_login(&request.login)?;
    let identity = handler
        .credentials
        .find_by_key(&handler.config.issuer, StandaloneCredentialKind::Password, &login)
        .await
        .map_err(ApiError::credential)?
        .ok_or_else(|| ApiError::unauthorized("WebAuthn authentication failed"))?;
    let credentials = handler
        .credentials
        .list_by_identity(&identity.credential.identity, StandaloneCredentialKind::Webauthn)
        .await
        .map_err(ApiError::credential)?;
    let (options, authentication) =
        webauthn.start_authentication(&credentials).map_err(webauthn_error)?;
    let challenge_id = random_id();
    put_json(
        handler.challenge_store()?,
        AUTHENTICATION_PURPOSE,
        &challenge_id,
        &AuthenticationChallenge {
            external_identity: identity.external_identity,
            state: authentication,
        },
        handler.challenge_ttl,
    )
    .await
    .map_err(ApiError::challenge)?;
    Ok(Json(AuthenticationChallengeResponse { challenge_id, options }))
}

pub(crate) async fn webauthn_authentication_verify(
    State(handler): State<StandaloneHandler>,
    headers: HeaderMap,
    Json(request): Json<AuthenticationVerifyRequest>,
) -> Result<LoginResponse, ApiError> {
    let return_to = crate::route::application::ApplicationResolver::new(
        authguard_common::config::AppConfig::get().get_authn(),
        &headers,
    )
    .validate_return_to(&request.return_to)?;
    let webauthn =
        handler.webauthn.as_ref().ok_or_else(|| ApiError::not_found("WebAuthn is not enabled"))?;
    let challenge = consume_json::<AuthenticationChallenge>(
        handler.challenge_store()?,
        AUTHENTICATION_PURPOSE,
        &request.challenge_id,
    )
    .await
    .map_err(ApiError::challenge)?
    .ok_or_else(|| ApiError::bad_request("invalid or expired WebAuthn challenge"))?;
    let identity_key = challenge
        .external_identity
        .key()
        .map_err(|_| ApiError::bad_request("invalid standalone identity"))?;
    let credentials = handler
        .credentials
        .list_by_identity(&identity_key, StandaloneCredentialKind::Webauthn)
        .await
        .map_err(ApiError::credential)?;
    let (credential_id, credential_data) = webauthn
        .finish_authentication(&request.credential, &challenge.state, &credentials)
        .map_err(webauthn_error)?;
    if let Some(data) = credential_data {
        let current_data = credentials
            .iter()
            .find(|credential| credential.id == credential_id)
            .and_then(|credential| credential.credential_data.as_ref())
            .ok_or_else(|| ApiError::unauthorized("WebAuthn authentication failed"))?;
        if !handler
            .credentials
            .compare_and_swap_credential_data(&credential_id, current_data, &data)
            .await
            .map_err(ApiError::credential)?
        {
            return Err(ApiError::unauthorized("WebAuthn authentication failed"));
        }
    }
    let authentication = DomainAuthenticationResult::new(
        challenge.external_identity,
        vec!["webauthn".to_string()],
        Some("urn:authguard:acr:webauthn:uv".to_string()),
        Utc::now(),
    );
    let issued = handler
        .pipeline
        .login(authentication, PrincipalKind::User)
        .await
        .map_err(ApiError::pipeline)?;
    Ok(LoginResponse::new(issued, return_to))
}

fn webauthn_error(error: WebauthnProviderError) -> ApiError {
    match error {
        WebauthnProviderError::InvalidCredentialData => {
            ApiError::internal("WebAuthn credential data is invalid")
        }
        WebauthnProviderError::UserVerificationRequired => {
            ApiError::unauthorized("WebAuthn user verification is required")
        }
        WebauthnProviderError::Ceremony | WebauthnProviderError::CredentialNotMatched => {
            ApiError::unauthorized("WebAuthn authentication failed")
        }
    }
}
