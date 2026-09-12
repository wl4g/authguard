//! Shared RS256 compact-JWT signing primitive used at AuthN/AuthZ boundaries.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer as _, Verifier as _};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use thiserror::Error;

const JWT_HEADER: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
const MIN_RSA_BITS: usize = 2_048;

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("signing key must be a PKCS#8 RSA private key of at least {MIN_RSA_BITS} bits")]
    InvalidSigningKey,
    #[error("JWT is malformed")]
    InvalidTokenFormat,
    #[error("JWT signature is invalid")]
    InvalidSignature,
}

#[derive(Clone)]
pub struct JwtSigningKey(rsa::pkcs1v15::SigningKey<Sha256>);

/// Loads an RS256 signing key from PKCS#8 PEM.
///
/// # Errors
///
/// Rejects malformed or RSA keys shorter than 2048 bits.
pub fn load_signing_key(private_key_pem: &str) -> Result<JwtSigningKey, JwtError> {
    let key =
        RsaPrivateKey::from_pkcs8_pem(private_key_pem).map_err(|_| JwtError::InvalidSigningKey)?;
    if key.n().bits() < MIN_RSA_BITS {
        return Err(JwtError::InvalidSigningKey);
    }
    key.validate().map_err(|_| JwtError::InvalidSigningKey)?;
    Ok(JwtSigningKey(rsa::pkcs1v15::SigningKey::new(key)))
}

/// Serializes the paired RSA public key as PKCS#1 PEM.
///
/// # Errors
///
/// Returns an error for an invalid in-memory key.
pub fn public_key_pem(key: &JwtSigningKey) -> Result<String, JwtError> {
    RsaPublicKey::from(key.0.as_ref())
        .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|_| JwtError::InvalidSigningKey)
}

/// Signs payload bytes as a compact RS256 JWT.
///
/// # Errors
///
/// Returns an error if signing fails.
pub fn sign(key: &JwtSigningKey, payload_bytes: &[u8]) -> Result<String, JwtError> {
    let signing_input = format!("{JWT_HEADER}.{}", URL_SAFE_NO_PAD.encode(payload_bytes));
    let signature = key.0.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())))
}

/// Verifies a compact JWT and returns its payload bytes.
///
/// # Errors
///
/// Rejects malformed tokens and invalid signatures.
pub fn verify(public_key_pem: &str, token: &str) -> Result<Vec<u8>, JwtError> {
    let public =
        RsaPublicKey::from_pkcs1_pem(public_key_pem).map_err(|_| JwtError::InvalidSigningKey)?;
    let mut parts = token.split('.');
    let header = parts.next();
    let payload = parts.next();
    let signature = parts.next();
    let Some((payload, signature)) = payload.zip(signature) else {
        return Err(JwtError::InvalidTokenFormat);
    };
    if header != Some(JWT_HEADER)
        || payload.is_empty()
        || signature.is_empty()
        || parts.next().is_some()
    {
        return Err(JwtError::InvalidTokenFormat);
    }
    let signature = URL_SAFE_NO_PAD.decode(signature).map_err(|_| JwtError::InvalidTokenFormat)?;
    let signing_input = format!("{JWT_HEADER}.{payload}");
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public);
    let signature = rsa::pkcs1v15::Signature::try_from(signature.as_slice())
        .map_err(|_| JwtError::InvalidTokenFormat)?;
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| JwtError::InvalidSignature)?;
    URL_SAFE_NO_PAD.decode(payload).map_err(|_| JwtError::InvalidTokenFormat)
}
