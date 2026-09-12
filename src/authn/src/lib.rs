//! Authentication and external-identity normalization for Authguard.
//!
//! This crate owns provider protocol differences and account linking. Its
//! output is a canonical [`AuthenticatedPrincipalContext`]; authorization
//! consumers never receive provider tokens or provider-specific identifiers.

pub mod handler;
pub mod principal;
pub mod provider;
pub mod route;
pub mod server;

pub use authguard_common::config;
pub use authguard_common::model;
pub use authguard_common::storage;
pub use principal::jit as account_linking;

pub use config::{
    AccountLinkingProperties, AuthnProperties, LinkingStrategy, ProviderProperties,
    SessionProperties,
};
pub use model::{
    AuthenticatedPrincipalContext, ExternalIdentity, ExternalIdentityKey, IamPrincipalInfo,
    PrincipalKind, PrincipalStatus,
};
pub use principal::{AccountLinkingError, AccountLinkingService, JitPrincipalDiscovery};
pub use provider::{
    GithubOauth2Provider, GoogleOauth2Provider, IProviderAdapter, OAuthLikeCallback,
    OAuthLikeProvider, ProviderError, ProviderTransport, QqOauth2Provider,
    ReqwestProviderTransport, WechatOauth2Provider,
};
pub use storage::{
    AuthnFlowRepository, AuthnFlowRepositoryError, IamAuthFlowInfo, IdentityBindingRepository,
    IdentityRepositoryError,
};
