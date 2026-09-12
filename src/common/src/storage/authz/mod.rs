//! `AuthZ` persistence boundary over the complete authorization aggregate.

mod role_postgres;
mod role_sqlite;

use async_trait::async_trait;
use thiserror::Error;

use crate::model::{IamPolicyInfo, IamPrincipalInfo, PrincipalStatus};

pub use role_postgres::AuthzPostgresRepository;
pub use role_sqlite::AuthzSqliteRepository;

#[async_trait]
pub trait PolicyRepository: Send + Sync {
    async fn ping(&self) -> anyhow::Result<()>;
    async fn load(&self) -> anyhow::Result<IamPolicyInfo>;
    async fn replace(&self, policy: &IamPolicyInfo) -> anyhow::Result<()>;
}

#[async_trait]
pub trait PrincipalRepository: Send + Sync {
    async fn upsert(&self, principal: &IamPrincipalInfo) -> anyhow::Result<IamPrincipalInfo>;
    async fn get(&self, id: &str) -> anyhow::Result<Option<IamPrincipalInfo>>;
    async fn find_by_ids(&self, ids: &[String]) -> anyhow::Result<Vec<IamPrincipalInfo>>;
    async fn list(
        &self,
        query: &str,
        after_id: Option<&str>,
        limit: u32,
    ) -> anyhow::Result<Vec<IamPrincipalInfo>>;
    async fn update_status(
        &self,
        id: &str,
        status: PrincipalStatus,
    ) -> anyhow::Result<Option<IamPrincipalInfo>>;
    async fn delete(&self, id: &str) -> anyhow::Result<bool>;
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("principal `{id}` is referenced by one or more role bindings")]
pub struct PrincipalReferenced {
    pub id: String,
}
