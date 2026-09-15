//! Standalone password and RFC 6238 TOTP protocol implementation.

use std::collections::BTreeMap;
use std::sync::Arc;

use authguard_common::cache::ICache;
use authguard_common::model::{
    AuthenticationResult, ExternalIdentity, IamStandaloneCredential, PrincipalKind,
    StandaloneCredentialIdentity, StandaloneCredentialKind,
};
use authguard_common::storage::StandaloneCredentialRepository;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::authentication::challenge::{consume_json, put_json};
use crate::authentication::random_id;
use crate::handler::{ApiError, AuthenticationPipeline, AuthnRuntime, LoginResponse};
use crate::provider::standalone::{PasswordVerifier, TotpService, WebauthnProvider};
use crate::StandaloneAuthnProperties;

pub(crate) use super::webauthn::{
    webauthn_authentication_challenge, webauthn_authentication_verify,
    webauthn_registration_challenge, webauthn_registration_verify,
};

const TOTP_ENROLLMENT_PURPOSE: &str = "standalone-totp-enrollment";

#[derive(Clone)]
pub(crate) struct StandaloneHandler {
    pub(super) config: StandaloneAuthnProperties,
    pub(super) credentials: Arc<dyn StandaloneCredentialRepository>,
    challenges: Option<Arc<dyn ICache>>,
    pub(super) pipeline: Arc<AuthenticationPipeline>,
    password: PasswordVerifier,
    totp: Option<TotpService>,
    pub(super) webauthn: Option<WebauthnProvider>,
    pub(super) challenge_ttl: std::time::Duration,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RegistrationRequest {
    login: String,
    password: String,
    display_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LoginRequest {
    pub(super) login: String,
    pub(super) password: String,
    pub(super) totp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TotpEnrollmentVerifyRequest {
    challenge_id: String,
    code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TotpEnrollmentResponse {
    challenge_id: String,
    secret: String,
    otpauth_uri: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TotpEnrollmentChallenge {
    external_identity: ExternalIdentity,
    credential_id: String,
    encrypted_secret: String,
}

impl StandaloneHandler {
    pub(crate) fn open(runtime: &AuthnRuntime) -> anyhow::Result<Option<Self>> {
        let application = authguard_common::config::AppConfig::get();
        let authn = application.get_authn();
        let config = authn.standalone.clone();
        if !config.enabled {
            return Ok(None);
        }
        let challenges = runtime.challenges.clone();
        if (config.totp.enabled || config.webauthn.enabled) && challenges.is_none() {
            anyhow::bail!("standalone TOTP/WebAuthn requires the challenge cache");
        }
        let totp = config
            .totp
            .enabled
            .then(|| TotpService::new(config.totp.clone(), &config.credential_encryption_key))
            .transpose()?;
        let webauthn =
            config.webauthn.enabled.then(|| WebauthnProvider::new(&config.webauthn)).transpose()?;
        Ok(Some(Self {
            password: PasswordVerifier::new(config.password.min_length)?,
            config,
            credentials: runtime.credentials.clone(),
            challenges,
            pipeline: runtime.pipeline.clone(),
            totp,
            webauthn,
            challenge_ttl: authn.challenge_ttl,
        }))
    }

    pub(super) async fn authenticate_credentials(
        &self,
        request: LoginRequest,
    ) -> Result<AuthenticationResult, ApiError> {
        let login = normalize_login(&request.login)?;
        let found = self
            .credentials
            .find_by_key(&self.config.issuer, StandaloneCredentialKind::Password, &login)
            .await
            .map_err(ApiError::credential)?;
        let hash = found.as_ref().and_then(|entry| entry.credential.secret_data.clone());
        if !self.password.verify(request.password, hash).await {
            return Err(ApiError::unauthorized("invalid credentials"));
        }
        let found = found.ok_or_else(|| ApiError::unauthorized("invalid credentials"))?;
        let mut amr = vec!["pwd".to_string()];
        let totp_credentials = self
            .credentials
            .list_by_identity(&found.credential.identity, StandaloneCredentialKind::Totp)
            .await
            .map_err(ApiError::credential)?;
        if !totp_credentials.is_empty() {
            let code = request.totp.ok_or_else(|| ApiError::unauthorized("TOTP is required"))?;
            if !self.verify_totp(&found, &totp_credentials, &code).await? {
                return Err(ApiError::unauthorized("invalid credentials"));
            }
            amr.push("otp".to_string());
        }
        Ok(AuthenticationResult::new(found.external_identity, amr, None, Utc::now()))
    }

    pub(super) fn challenge_store(&self) -> Result<&dyn ICache, ApiError> {
        self.challenges
            .as_deref()
            .ok_or_else(|| ApiError::not_found("interactive standalone authentication is disabled"))
    }

    async fn verify_totp(
        &self,
        identity: &StandaloneCredentialIdentity,
        credentials: &[IamStandaloneCredential],
        code: &str,
    ) -> Result<bool, ApiError> {
        let service = self
            .totp
            .as_ref()
            .ok_or_else(|| ApiError::internal("TOTP verifier is not configured"))?;
        for credential in credentials {
            let Some(encrypted) = credential.secret_data.as_deref() else {
                continue;
            };
            let secret = service.decrypt(encrypted, &credential.id).map_err(|error| {
                tracing::error!(%error, credential_id = %credential.id, "decrypt TOTP secret failed");
                ApiError::internal("TOTP credential could not be verified")
            })?;
            let counter = service
                .check(&secret, &identity.external_identity.subject, code)
                .map_err(|_| ApiError::unauthorized("invalid credentials"))?;
            if let Some(counter) = counter {
                if self
                    .credentials
                    .advance_totp_counter(&credential.id, counter)
                    .await
                    .map_err(ApiError::credential)?
                {
                    return Ok(true);
                }
                return Ok(false);
            }
        }
        Ok(false)
    }
}

pub(crate) async fn register(
    State(state): State<StandaloneHandler>,
    headers: HeaderMap,
    Json(request): Json<RegistrationRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let login = normalize_login(&request.login)?;
    if !state.password.validate_new(&request.password) {
        return Err(ApiError::bad_request("password does not meet the configured policy"));
    }
    if request.display_name.trim().is_empty() || request.display_name.len() > 256 {
        return Err(ApiError::bad_request("displayName is required"));
    }
    if state
        .credentials
        .find_by_key(&state.config.issuer, StandaloneCredentialKind::Password, &login)
        .await
        .map_err(ApiError::credential)?
        .is_some()
    {
        return Err(ApiError::conflict("credential identifier is already registered"));
    }
    let subject = format!("local_{}", random_id());
    let identity = ExternalIdentity {
        provider: "standalone".to_string(),
        issuer: state.config.issuer.clone(),
        subject,
        claims: BTreeMap::from([(
            "display_name".to_string(),
            serde_json::Value::String(request.display_name.trim().to_string()),
        )]),
    };
    let password_hash = state.password.hash(request.password).await.map_err(|error| {
        tracing::error!(%error, "Argon2id password hashing failed");
        ApiError::internal("password credential could not be created")
    })?;
    let authentication =
        AuthenticationResult::new(identity.clone(), vec!["pwd".to_string()], None, Utc::now());
    let identity_key =
        identity.key().map_err(|_| ApiError::internal("standalone identity is invalid"))?;
    let issued = if headers.contains_key(axum::http::header::AUTHORIZATION) {
        let principal_id = state.pipeline.authenticate_token(&headers).map_err(ApiError::token)?;
        state.pipeline.link(&principal_id, authentication).await
    } else {
        state.pipeline.login(authentication, PrincipalKind::User).await
    }
    .map_err(ApiError::pipeline)?;
    if let Err(error) = state
        .credentials
        .create_credential(&IamStandaloneCredential {
            id: format!("pwd_{}", random_id()),
            identity: identity_key.clone(),
            kind: StandaloneCredentialKind::Password,
            credential_key: Some(login),
            secret_data: Some(password_hash),
            credential_data: None,
        })
        .await
    {
        if let Err(rollback) = state
            .pipeline
            .rollback_identity_binding(&issued.principal.principal_id, &identity_key)
            .await
        {
            tracing::error!(%rollback, "failed to roll back incomplete standalone registration");
            return Err(ApiError::internal("standalone registration rollback failed"));
        }
        return Err(ApiError::credential(error));
    }
    Ok(Json(LoginResponse::new(issued, String::new())))
}

pub(crate) async fn login(
    State(state): State<StandaloneHandler>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let authentication = state.authenticate_credentials(request).await?;
    let issued = state
        .pipeline
        .login(authentication, PrincipalKind::User)
        .await
        .map_err(ApiError::pipeline)?;
    Ok(Json(LoginResponse::new(issued, String::new())))
}

pub(crate) async fn totp_enrollment_challenge(
    State(state): State<StandaloneHandler>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<TotpEnrollmentResponse>, ApiError> {
    let authentication = state.authenticate_credentials(request).await?;
    let service = state.totp.as_ref().ok_or_else(|| ApiError::not_found("TOTP is not enabled"))?;
    let credential_id = format!("totp_{}", random_id());
    let (secret, otpauth_uri) = service
        .generate(&authentication.external_identity.subject)
        .map_err(|_| ApiError::internal("TOTP enrollment could not be started"))?;
    let encrypted_secret = service
        .encrypt(&secret, &credential_id)
        .map_err(|_| ApiError::internal("TOTP enrollment could not be started"))?;
    let challenge_id = random_id();
    put_json(
        state.challenge_store()?,
        TOTP_ENROLLMENT_PURPOSE,
        &challenge_id,
        &TotpEnrollmentChallenge {
            external_identity: authentication.external_identity,
            credential_id,
            encrypted_secret,
        },
        state.challenge_ttl,
    )
    .await
    .map_err(ApiError::challenge)?;
    Ok(Json(TotpEnrollmentResponse { challenge_id, secret, otpauth_uri }))
}

pub(crate) async fn totp_enrollment_verify(
    State(state): State<StandaloneHandler>,
    Json(request): Json<TotpEnrollmentVerifyRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let service = state.totp.as_ref().ok_or_else(|| ApiError::not_found("TOTP is not enabled"))?;
    let challenge = consume_json::<TotpEnrollmentChallenge>(
        state.challenge_store()?,
        TOTP_ENROLLMENT_PURPOSE,
        &request.challenge_id,
    )
    .await
    .map_err(ApiError::challenge)?
    .ok_or_else(|| ApiError::bad_request("invalid or expired TOTP enrollment"))?;
    let secret = service
        .decrypt(&challenge.encrypted_secret, &challenge.credential_id)
        .map_err(|_| ApiError::bad_request("invalid or expired TOTP enrollment"))?;
    let counter = service
        .check(&secret, &challenge.external_identity.subject, &request.code)
        .map_err(|_| ApiError::unauthorized("invalid TOTP code"))?
        .ok_or_else(|| ApiError::unauthorized("invalid TOTP code"))?;
    state
        .credentials
        .create_credential(&IamStandaloneCredential {
            id: challenge.credential_id,
            identity: challenge
                .external_identity
                .key()
                .map_err(|_| ApiError::bad_request("invalid standalone identity"))?,
            kind: StandaloneCredentialKind::Totp,
            credential_key: None,
            secret_data: Some(challenge.encrypted_secret),
            credential_data: Some(json!({"lastCounter": counter})),
        })
        .await
        .map_err(ApiError::credential)?;
    let authentication = AuthenticationResult::new(
        challenge.external_identity,
        vec!["pwd".to_string(), "otp".to_string()],
        None,
        Utc::now(),
    );
    let issued = state
        .pipeline
        .login(authentication, PrincipalKind::User)
        .await
        .map_err(ApiError::pipeline)?;
    Ok(Json(LoginResponse::new(issued, String::new())))
}

pub(super) fn normalize_login(login: &str) -> Result<String, ApiError> {
    let login = login.trim().to_lowercase();
    if login.is_empty() || login.len() > 320 {
        return Err(ApiError::bad_request("login must be between 1 and 320 bytes"));
    }
    Ok(login)
}
