//! `AuthN` persistence boundary over `iam_authn_flow`, `iam_principal`, and
//! `iam_principal_identity`.

mod flow_postgres;
mod flow_sqlite;

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

pub use crate::model::IamAuthFlowInfo;
use crate::model::{ExternalIdentity, ExternalIdentityKey};
use crate::IamPrincipalInfo;

pub use super::principal_postgres::AuthnPostgresRepository;
pub use super::principal_sqlite::AuthnSqliteRepository;

#[derive(Debug, Error, PartialEq, Eq)]
#[error("authentication flow repository failed: {0}")]
pub struct AuthnFlowRepositoryError(pub String);

#[async_trait]
pub trait AuthnFlowRepository: Send + Sync {
    async fn create(
        &self,
        state_hash: &str,
        flow: &IamAuthFlowInfo,
    ) -> Result<(), AuthnFlowRepositoryError>;
    async fn consume(
        &self,
        state_hash: &str,
    ) -> Result<Option<IamAuthFlowInfo>, AuthnFlowRepositoryError>;
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityRepositoryError {
    #[error("external identity is already bound to another Principal")]
    IdentityAlreadyBound,
    #[error("identity repository failed: {0}")]
    Backend(String),
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
