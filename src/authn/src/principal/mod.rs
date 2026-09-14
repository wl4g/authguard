//! Canonical Principal discovery and protocol-independent identity linking.

pub mod jit;

pub use jit::{AccountLinkingError, AccountLinkingService, JitPrincipalDiscovery};
