//! `WebAuthn` protocol adapter; all cryptographic validation stays in `webauthn-rs`.

use std::sync::Arc;

use authguard_common::model::{ExternalIdentityKey, IamStandaloneCredential};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Webauthn,
    WebauthnBuilder,
};

use crate::WebauthnProperties;

#[derive(Clone)]
pub(crate) struct WebauthnProvider {
    server: Arc<Webauthn>,
}

#[derive(Clone, Copy, Debug, Error)]
pub(crate) enum WebauthnProviderError {
    #[error("WebAuthn ceremony validation failed")]
    Ceremony,
    #[error("WebAuthn user verification is required")]
    UserVerificationRequired,
    #[error("WebAuthn credential data is invalid")]
    InvalidCredentialData,
    #[error("WebAuthn credential did not match")]
    CredentialNotMatched,
}

impl WebauthnProvider {
    pub(crate) fn new(configuration: &WebauthnProperties) -> anyhow::Result<Self> {
        let origin = Url::parse(&configuration.rp_origin)?;
        let mut builder = WebauthnBuilder::new(&configuration.rp_id, &origin)?;
        builder = builder.rp_name(&configuration.rp_name);
        Ok(Self { server: Arc::new(builder.build()?) })
    }

    pub(crate) fn start_registration(
        &self,
        identity: &ExternalIdentityKey,
        display_name: &str,
        credentials: &[IamStandaloneCredential],
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), WebauthnProviderError> {
        let exclude = credentials
            .iter()
            .map(parse_passkey)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|passkey| passkey.cred_id().clone())
            .collect::<Vec<_>>();
        let user_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("{}:{}", identity.issuer, identity.subject).as_bytes(),
        );
        self.server
            .start_passkey_registration(
                user_id,
                &identity.subject,
                display_name,
                (!exclude.is_empty()).then_some(exclude),
            )
            .map_err(ceremony_error)
    }

    pub(crate) fn finish_registration(
        &self,
        credential: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<(String, Value), WebauthnProviderError> {
        let passkey =
            self.server.finish_passkey_registration(credential, state).map_err(ceremony_error)?;
        Ok((
            URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref()),
            serde_json::to_value(passkey)
                .map_err(|_| WebauthnProviderError::InvalidCredentialData)?,
        ))
    }

    pub(crate) fn start_authentication(
        &self,
        credentials: &[IamStandaloneCredential],
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), WebauthnProviderError> {
        let passkeys = credentials.iter().map(parse_passkey).collect::<Result<Vec<_>, _>>()?;
        if passkeys.is_empty() {
            return Err(WebauthnProviderError::CredentialNotMatched);
        }
        self.server.start_passkey_authentication(&passkeys).map_err(ceremony_error)
    }

    pub(crate) fn finish_authentication(
        &self,
        credential: &PublicKeyCredential,
        state: &PasskeyAuthentication,
        credentials: &[IamStandaloneCredential],
    ) -> Result<(String, Option<Value>), WebauthnProviderError> {
        let verified =
            self.server.finish_passkey_authentication(credential, state).map_err(ceremony_error)?;
        if !verified.user_verified() {
            return Err(WebauthnProviderError::UserVerificationRequired);
        }
        for credential in credentials {
            let mut passkey = parse_passkey(credential)?;
            if let Some(changed) = passkey.update_credential(&verified) {
                return Ok((
                    credential.id.clone(),
                    changed
                        .then(|| serde_json::to_value(passkey))
                        .transpose()
                        .map_err(|_| WebauthnProviderError::InvalidCredentialData)?,
                ));
            }
        }
        Err(WebauthnProviderError::CredentialNotMatched)
    }
}

fn parse_passkey(credential: &IamStandaloneCredential) -> Result<Passkey, WebauthnProviderError> {
    credential.credential_data.clone().ok_or(WebauthnProviderError::InvalidCredentialData).and_then(
        |value| {
            serde_json::from_value(value).map_err(|_| WebauthnProviderError::InvalidCredentialData)
        },
    )
}

fn ceremony_error(error: webauthn_rs::prelude::WebauthnError) -> WebauthnProviderError {
    tracing::warn!(%error, "WebAuthn ceremony validation failed");
    drop(error);
    WebauthnProviderError::Ceremony
}
