//! Shared persistence boundary over one canonical IAM database.
//!
//! `base_sqlite` and `base_postgres` own database mechanics, shared `principal_*`
//! modules own the canonical Principal aggregate, and service submodules own
//! only their exclusive flow or authorization tables.

pub mod authn;
pub mod authz;
mod base_postgres;
mod base_sqlite;
mod principal_postgres;
mod principal_sqlite;

pub use authn::{
    AuthnFlowRepository, AuthnFlowRepositoryError, AuthnPostgresRepository, AuthnSqliteRepository,
    IamAuthFlowInfo, IdentityBindingRepository, IdentityRepositoryError,
};
pub use authz::{
    AuthzPostgresRepository, AuthzSqliteRepository, PolicyRepository, PrincipalIdentityConflict,
    PrincipalReferenced, PrincipalRepository,
};
pub use base_postgres::PostgresRepository;
pub use base_sqlite::SqliteRepository;

/// The single authoritative IAM schema shared by `AuthN` and `AuthZ`.
pub const IAM_SCHEMA_DDL: &str = include_str!("../../../../migrations/001_init.ddl.sql");
pub const IAM_BOOTSTRAP_DML: &str = include_str!("../../../../migrations/001_init.dml.sql");
const IAM_SCHEMA_LOCK: i64 = 0x4155_5448_4755_4152;

/// Entity-independent database repository contract composed by AuthN/AuthZ repositories.
pub trait IAsyncRepository: Send + Sync {
    type Database: sqlx::Database;
    fn pool(&self) -> &sqlx::Pool<Self::Database>;
}
