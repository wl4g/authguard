//! Protocol-neutral authentication primitives shared by every provider.

pub(crate) mod challenge;
mod token;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore as _;

pub(crate) use token::{TokenError, TokenIssuer};

#[must_use]
pub(crate) fn random_id() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
