//! Shared building blocks for OAuth2-like provider adapters.

pub(in crate::provider) mod normalization;
mod oauth2_like;

pub use oauth2_like::OAuthLikeProvider;
