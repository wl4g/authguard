//! Standalone credential protocol implementations without persistence or HTTP concerns.

mod password;
mod totp;
mod webauthn;

pub(crate) use password::PasswordVerifier;
pub(crate) use totp::TotpService;
pub(crate) use webauthn::{WebauthnProvider, WebauthnProviderError};
