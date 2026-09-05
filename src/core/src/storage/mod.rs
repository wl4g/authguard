mod postgres;
mod record;
mod sqlite;

use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use thiserror::Error;

use crate::config::StorageConfig;
use crate::model::{Policy, Principal, PrincipalStatus};

pub use postgres::PostgresAuthorizationRepository;
pub use sqlite::SqliteAuthorizationRepository;

/// Durable repositories backed by one shared database pool.
///
/// Principal projections intentionally remain outside the policy aggregate: a
/// deployment may discover millions of principals while its active policy is
/// small enough to cache as one immutable snapshot.
#[derive(Clone)]
pub struct Repositories {
    pub policy: Arc<dyn PolicyRepository>,
    pub principals: Arc<dyn PrincipalRepository>,
}

#[async_trait]
pub trait PolicyRepository: Send + Sync {
    /// Verifies that the durable authorization store is reachable.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot execute a minimal query.
    async fn ping(&self) -> anyhow::Result<()>;

    /// Loads the single active authorization policy.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or invalid.
    async fn load(&self) -> anyhow::Result<Policy>;

    /// Atomically replaces the policy only when its persisted revision still
    /// equals `expected_revision`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyRevisionConflict`] for a stale writer, or an error when
    /// policy validation or transactional persistence fails.
    async fn compare_and_replace(
        &self,
        expected_revision: u64,
        policy: &Policy,
    ) -> anyhow::Result<()>;
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("policy revision conflict: expected {expected}, persisted revision is {actual}")]
pub struct PolicyRevisionConflict {
    pub expected: u64,
    pub actual: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("principal `{id}` is referenced by one or more role bindings")]
pub struct PrincipalReferenced {
    pub id: String,
}

#[async_trait]
pub trait PrincipalRepository: Send + Sync {
    /// Creates or refreshes a trusted external-principal projection.
    ///
    /// `(issuer, external_id)` is the external identity key. An existing
    /// projection keeps its Authguard-owned `id` during an upsert.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or durable persistence fails.
    async fn upsert(&self, principal: &Principal) -> anyhow::Result<Principal>;

    /// Loads one projection by its Authguard-owned identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state cannot be queried or decoded.
    async fn get(&self, id: &str) -> anyhow::Result<Option<Principal>>;

    /// Loads one projection by its issuer-scoped external identity.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state cannot be queried or decoded.
    async fn find_by_external_key(
        &self,
        issuer: &str,
        external_id: &str,
    ) -> anyhow::Result<Option<Principal>>;

    /// Loads a bounded set of projections for one issuer in a single query.
    /// This is the authorization hot-path operation for one primary identity
    /// plus its group claims.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state cannot be queried or decoded.
    async fn find_by_external_keys(
        &self,
        issuer: &str,
        external_ids: &[String],
    ) -> anyhow::Result<Vec<Principal>>;

    /// Lists locally projected principals using an ID cursor. `query` is an
    /// optional case-insensitive prefix over display name and external ID.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state cannot be queried or decoded.
    async fn list(
        &self,
        query: &str,
        after_id: Option<&str>,
        limit: u32,
    ) -> anyhow::Result<Vec<Principal>>;

    /// Changes the local projection status, returning `None` when it is absent.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state cannot be updated or decoded.
    async fn update_status(
        &self,
        id: &str,
        status: PrincipalStatus,
    ) -> anyhow::Result<Option<Principal>>;

    /// Deletes an unreferenced projection, returning whether it existed.
    /// Role-binding foreign keys deliberately reject deletion while in use.
    ///
    /// # Errors
    ///
    /// Returns an error when deletion fails, including referential-integrity
    /// failures for a principal referenced by a role binding.
    async fn delete(&self, id: &str) -> anyhow::Result<bool>;
}

/// Opens both repositories over one shared provider pool.
///
/// # Errors
///
/// Returns an error for an unsupported provider or failed database initialization.
pub async fn open(storage: &StorageConfig) -> anyhow::Result<Repositories> {
    match storage.provider.to_ascii_lowercase().as_str() {
        "sqlite" => {
            let repository = Arc::new(
                SqliteAuthorizationRepository::connect(&storage.sqlite)
                    .await
                    .context("open SQLite authorization repositories")?,
            );
            Ok(Repositories { policy: repository.clone(), principals: repository })
        }
        "postgres" => {
            let repository = Arc::new(
                PostgresAuthorizationRepository::connect(&storage.postgres)
                    .await
                    .context("open PostgreSQL authorization repositories")?,
            );
            Ok(Repositories { policy: repository.clone(), principals: repository })
        }
        provider => anyhow::bail!("unsupported authorization storage provider `{provider}`"),
    }
}
