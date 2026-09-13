//! `WebAuthn` ceremony adapter. Cryptography and RP/origin validation are
//! delegated to the audited `webauthn-rs` implementation.

use std::sync::Arc;

use authguard_common::model::{
    AuthenticationResult as DomainAuthenticationResult, ExternalIdentity, IamStandaloneCredential,
    PrincipalKind, StandaloneCredentialKind,
};
use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Webauthn,
    WebauthnBuilder,
};

use super::{normalize_login, LoginRequest, StandaloneHandler};
use crate::challenge::{consume_json, put_json, random_challenge_id};
use crate::handler::{ApiError, LoginResponse};
use crate::WebauthnProperties;

const REGISTRATION_PURPOSE: &str = "standalone-webauthn-registration";
const AUTHENTICATION_PURPOSE: &str = "standalone-webauthn-authentication";

#[derive(Clone)]
pub(super) struct WebauthnService {
    server: Arc<Webauthn>,
}

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
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationChallenge {
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

impl WebauthnService {
    pub(super) fn new(configuration: &WebauthnProperties) -> anyhow::Result<Self> {
        let origin = Url::parse(&configuration.rp_origin)?;
        let mut builder = WebauthnBuilder::new(&configuration.rp_id, &origin)?;
        builder = builder.rp_name(&configuration.rp_name);
        Ok(Self { server: Arc::new(builder.build()?) })
    }

    fn server(&self) -> &Webauthn {
        &self.server
    }
}

pub(crate) async fn webauthn_registration_challenge(
    State(handler): State<StandaloneHandler>,
    Json(request): Json<RegistrationChallengeRequest>,
) -> Result<Json<RegistrationChallengeResponse>, ApiError> {
    let webauthn =
        handler.webauthn.as_ref().ok_or_else(|| ApiError::not_found("WebAuthn is not enabled"))?;
    let authentication = handler
        .authenticate_credentials(LoginRequest {
            login: request.login,
            password: request.password,
            totp: request.totp,
        })
        .await?;
    let identity_key = authentication
        .external_identity
        .key()
        .map_err(|_| ApiError::internal("standalone identity is invalid"))?;
    let existing = handler
        .credentials
        .list_by_identity(&identity_key, StandaloneCredentialKind::Webauthn)
        .await
        .map_err(ApiError::credential)?;
    let exclude = existing
        .iter()
        .map(parse_passkey)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|passkey| passkey.cred_id().clone())
        .collect::<Vec<CredentialID>>();
    let user_id = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("{}:{}", identity_key.issuer, identity_key.subject).as_bytes(),
    );
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
        .server()
        .start_passkey_registration(
            user_id,
            &authentication.external_identity.subject,
            &display_name,
            (!exclude.is_empty()).then_some(exclude),
        )
        .map_err(webauthn_error)?;
    let challenge_id = random_challenge_id();
    put_json(
        handler.challenge_store()?,
        REGISTRATION_PURPOSE,
        &challenge_id,
        &RegistrationChallenge {
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
    Json(request): Json<RegistrationVerifyRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let webauthn =
        handler.webauthn.as_ref().ok_or_else(|| ApiError::not_found("WebAuthn is not enabled"))?;
    let challenge = consume_json::<RegistrationChallenge>(
        handler.challenge_store()?,
        REGISTRATION_PURPOSE,
        &request.challenge_id,
    )
    .await
    .map_err(ApiError::challenge)?
    .ok_or_else(|| ApiError::bad_request("invalid or expired WebAuthn challenge"))?;
    let passkey = webauthn
        .server()
        .finish_passkey_registration(&request.credential, &challenge.state)
        .map_err(webauthn_error)?;
    let credential_key = URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref());
    handler
        .credentials
        .create_credential(&IamStandaloneCredential {
            id: format!("webauthn_{}", random_challenge_id()),
            identity: challenge
                .external_identity
                .key()
                .map_err(|_| ApiError::bad_request("invalid standalone identity"))?,
            kind: StandaloneCredentialKind::Webauthn,
            credential_key: Some(credential_key),
            secret_data: None,
            credential_data: Some(
                serde_json::to_value(passkey).map_err(|_| {
                    ApiError::internal("WebAuthn credential could not be serialized")
                })?,
            ),
        })
        .await
        .map_err(ApiError::credential)?;
    let authentication = DomainAuthenticationResult::new(
        challenge.external_identity,
        challenge.amr.into_iter().chain(["webauthn".to_string()]),
        Some("urn:authguard:acr:webauthn:uv".to_string()),
        Utc::now(),
    );
    let session = handler
        .pipeline
        .login(authentication, PrincipalKind::User)
        .await
        .map_err(ApiError::pipeline)?;
    Ok(Json(LoginResponse::new(session, String::new())))
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
    let passkeys = credentials.iter().map(parse_passkey).collect::<Result<Vec<_>, _>>()?;
    if passkeys.is_empty() {
        return Err(ApiError::unauthorized("WebAuthn authentication failed"));
    }
    let (options, authentication) =
        webauthn.server().start_passkey_authentication(&passkeys).map_err(webauthn_error)?;
    let challenge_id = random_challenge_id();
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
    Json(request): Json<AuthenticationVerifyRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
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
    let verified = webauthn
        .server()
        .finish_passkey_authentication(&request.credential, &challenge.state)
        .map_err(webauthn_error)?;
    if !verified.user_verified() {
        return Err(ApiError::unauthorized("WebAuthn user verification is required"));
    }
    let identity_key = challenge
        .external_identity
        .key()
        .map_err(|_| ApiError::bad_request("invalid standalone identity"))?;
    let credentials = handler
        .credentials
        .list_by_identity(&identity_key, StandaloneCredentialKind::Webauthn)
        .await
        .map_err(ApiError::credential)?;
    let mut matched = false;
    for credential in credentials {
        let mut passkey = parse_passkey(&credential)?;
        if let Some(changed) = passkey.update_credential(&verified) {
            matched = true;
            if changed {
                let data = serde_json::to_value(passkey)
                    .map_err(|_| ApiError::internal("WebAuthn credential update failed"))?;
                if !handler
                    .credentials
                    .update_credential_data(&credential.id, &data)
                    .await
                    .map_err(ApiError::credential)?
                {
                    return Err(ApiError::unauthorized("WebAuthn authentication failed"));
                }
            }
            break;
        }
    }
    if !matched {
        return Err(ApiError::unauthorized("WebAuthn authentication failed"));
    }
    let authentication = DomainAuthenticationResult::new(
        challenge.external_identity,
        vec!["webauthn".to_string()],
        Some("urn:authguard:acr:webauthn:uv".to_string()),
        Utc::now(),
    );
    let session = handler
        .pipeline
        .login(authentication, PrincipalKind::User)
        .await
        .map_err(ApiError::pipeline)?;
    Ok(Json(LoginResponse::new(session, String::new())))
}

fn parse_passkey(credential: &IamStandaloneCredential) -> Result<Passkey, ApiError> {
    credential
        .credential_data
        .clone()
        .ok_or_else(|| ApiError::internal("WebAuthn credential data is missing"))
        .and_then(|value| {
            serde_json::from_value(value)
                .map_err(|_| ApiError::internal("WebAuthn credential data is invalid"))
        })
}

fn webauthn_error(error: webauthn_rs::prelude::WebauthnError) -> ApiError {
    tracing::warn!(%error, "WebAuthn ceremony validation failed");
    drop(error);
    ApiError::unauthorized("WebAuthn ceremony validation failed")
}
