//! RS256 re-signing of the JWT delivered to business microservices.
//!
//! See [`jwt`] for the utility functions and the rationale.

mod jwt;

pub use jwt::{load_signing_key, public_key_pem, sign, verify, ResignJwtError, SigningKey};
