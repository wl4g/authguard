//! Authentication and external-identity normalization for Authguard.
//!
//! This crate owns provider protocol differences and account linking. Its
//! output is a canonical [`AuthenticatedPrincipalContext`]; authorization
//! consumers never receive provider tokens or provider-specific identifiers.

pub mod challenge;
pub mod handler;
pub mod pipeline;
pub mod principal;
pub mod provider;
pub mod route;
pub mod runtime;
pub mod server;
pub mod session;
pub mod standalone;
#[cfg(feature = "web3")]
pub mod wallet;

pub use authguard_common::config;
pub use authguard_common::model;
pub use authguard_common::storage;
pub use principal::jit as account_linking;

pub use config::{
    AccountLinkingProperties, AuthnProperties, BitcoinWalletChainProperties,
    EvmWalletChainProperties, LinkingStrategy, OidcProviderProperties, ProviderProperties,
    SessionProperties, StandaloneAuthnProperties, WalletAuthnProperties, WalletChainsProperties,
    WebauthnProperties,
};
pub use model::{
    AuthenticatedPrincipalContext, AuthenticationResult, ExternalIdentity, ExternalIdentityKey,
    IamPrincipalInfo, PrincipalKind, PrincipalStatus,
};
pub use principal::{AccountLinkingError, AccountLinkingService, JitPrincipalDiscovery};
pub use provider::{
    GithubOauth2Provider, GoogleOauth2Provider, IProviderAdapter, OAuthLikeCallback,
    OAuthLikeProvider, OidcProvider, ProviderError, ProviderTransport, QqOauth2Provider,
    ReqwestProviderTransport, WechatOauth2Provider,
};
pub use storage::{
    CredentialRepositoryError, IdentityBindingRepository, IdentityRepositoryError,
    StandaloneCredentialRepository,
};
