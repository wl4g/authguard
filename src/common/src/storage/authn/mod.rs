//! `AuthN` persistence boundary over canonical identities and the single
//! standalone credential table. All ceremony/challenge state lives in Redis.

mod credential_postgres;
mod credential_sqlite;

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

use crate::model::{
    ExternalIdentity, ExternalIdentityKey, IamStandaloneCredential, StandaloneCredentialIdentity,
    StandaloneCredentialKind,
};
use crate::IamPrincipalInfo;

pub use super::principal_postgres::AuthnPostgresRepository;
pub use super::principal_sqlite::AuthnSqliteRepository;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityRepositoryError {
    #[error("external identity is already bound to another Principal")]
    IdentityAlreadyBound,
    #[error("identity repository failed: {0}")]
    Backend(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CredentialRepositoryError {
    #[error("standalone credential key is already registered")]
    KeyConflict,
    #[error("standalone credential repository failed: {0}")]
    Backend(String),
}

#[async_trait]
pub trait StandaloneCredentialRepository: Send + Sync {
    async fn find_by_key(
        &self,
        issuer: &str,
        kind: StandaloneCredentialKind,
        credential_key: &str,
    ) -> Result<Option<StandaloneCredentialIdentity>, CredentialRepositoryError>;

    async fn list_by_identity(
        &self,
        identity: &ExternalIdentityKey,
        kind: StandaloneCredentialKind,
    ) -> Result<Vec<IamStandaloneCredential>, CredentialRepositoryError>;

    async fn create_credential(
        &self,
        credential: &IamStandaloneCredential,
    ) -> Result<(), CredentialRepositoryError>;

    async fn update_credential_data(
        &self,
        credential_id: &str,
        credential_data: &serde_json::Value,
    ) -> Result<bool, CredentialRepositoryError>;

    async fn advance_totp_counter(
        &self,
        credential_id: &str,
        counter: u64,
    ) -> Result<bool, CredentialRepositoryError>;
}

#[async_trait]
pub trait IdentityBindingRepository: Send + Sync {
    async fn find_principal_by_identity(
        &self,
        identity: &ExternalIdentityKey,
    ) -> Result<Option<IamPrincipalInfo>, IdentityRepositoryError>;
    async fn create_principal_and_bind(
        &self,
        principal: &IamPrincipalInfo,
        identity: &ExternalIdentity,
    ) -> Result<IamPrincipalInfo, IdentityRepositoryError>;
    async fn bind_identity(
        &self,
        principal_id: &str,
        identity: &ExternalIdentity,
    ) -> Result<IamPrincipalInfo, IdentityRepositoryError>;
    async fn principal_has_provider(
        &self,
        principal_id: &str,
        provider: &str,
    ) -> Result<bool, IdentityRepositoryError>;
}

#[async_trait]
impl<T: IdentityBindingRepository + ?Sized> IdentityBindingRepository for Arc<T> {
    async fn find_principal_by_identity(
        &self,
        identity: &ExternalIdentityKey,
    ) -> Result<Option<IamPrincipalInfo>, IdentityRepositoryError> {
        (**self).find_principal_by_identity(identity).await
    }
    async fn create_principal_and_bind(
        &self,
        principal: &IamPrincipalInfo,
        identity: &ExternalIdentity,
    ) -> Result<IamPrincipalInfo, IdentityRepositoryError> {
        (**self).create_principal_and_bind(principal, identity).await
    }
    async fn bind_identity(
        &self,
        principal_id: &str,
        identity: &ExternalIdentity,
    ) -> Result<IamPrincipalInfo, IdentityRepositoryError> {
        (**self).bind_identity(principal_id, identity).await
    }
    async fn principal_has_provider(
        &self,
        principal_id: &str,
        provider: &str,
    ) -> Result<bool, IdentityRepositoryError> {
        (**self).principal_has_provider(principal_id, provider).await
    }
}

#[async_trait]
impl<T: StandaloneCredentialRepository + ?Sized> StandaloneCredentialRepository for Arc<T> {
    async fn find_by_key(
        &self,
        issuer: &str,
        kind: StandaloneCredentialKind,
        credential_key: &str,
    ) -> Result<Option<StandaloneCredentialIdentity>, CredentialRepositoryError> {
        (**self).find_by_key(issuer, kind, credential_key).await
    }

    async fn list_by_identity(
        &self,
        identity: &ExternalIdentityKey,
        kind: StandaloneCredentialKind,
    ) -> Result<Vec<IamStandaloneCredential>, CredentialRepositoryError> {
        (**self).list_by_identity(identity, kind).await
    }

    async fn create_credential(
        &self,
        credential: &IamStandaloneCredential,
    ) -> Result<(), CredentialRepositoryError> {
        (**self).create_credential(credential).await
    }

    async fn update_credential_data(
        &self,
        credential_id: &str,
        credential_data: &serde_json::Value,
    ) -> Result<bool, CredentialRepositoryError> {
        (**self).update_credential_data(credential_id, credential_data).await
    }

    async fn advance_totp_counter(
        &self,
        credential_id: &str,
        counter: u64,
    ) -> Result<bool, CredentialRepositoryError> {
        (**self).advance_totp_counter(credential_id, counter).await
    }
}
