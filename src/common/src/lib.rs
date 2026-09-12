//! Shared, protocol-neutral `AuthGuard` contracts and infrastructure.
//!
//! This crate contains only concepts used by more than one server. Provider
//! protocol behavior remains in `AuthN`; authorization policy and scope caches
//! remain in `AuthZ`.

pub mod apm;
pub mod cache;
pub mod config;
pub mod model;
pub mod principal;
pub mod route;
pub mod storage;
pub mod utils;

pub use config::{
    CacheProperties, LoggingProperties, MemoryCacheProperties, MetricsProperties, OtelProperties,
    PostgresProperties, RedisClusterProperties, SqliteProperties, StorageProperties,
};
pub use model::{
    AuthenticatedPrincipalContext, IamPrincipalInfo, IdentityError, PrincipalKind, PrincipalStatus,
};
pub use utils::{
    access_context_v1, epoch_seconds, AccessContext, AccessContextError, AccessContextInput,
    AccessContextSigner, PathMap, PathPattern, ResourceSqlMapping, ResourceUrn, SegmentMap,
    SegmentPattern, SqlCompileError, SqlScope, UrnError, UrnPattern, ACCESS_CONTEXT_HEADER,
    ACCESS_CONTEXT_SIGNING_KEY_ENV, ACCESS_CONTEXT_VERSION, SCOPE_TOKEN_HEADER,
};
