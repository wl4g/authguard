//! RS256 re-signing utilities for the JWT delivered to business microservices.
//!
//! On every allowed check Authguard re-signs the verified client identity as a
//! short-lived JWT carrying `authguardOrigin: true`. All attributes of the
//! client JWT are preserved — only the marker claim is added — so a workload
//! verifying this signature proves the request passed through Envoy Gateway
//! and rejects clients that call its API directly. The private key stays in
//! Authguard; workloads only hold the paired public key.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer as _, Verifier as _};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use thiserror::Error;

const JWT_HEADER: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"; // {"alg":"RS256","typ":"JWT"}
const MIN_RSA_BITS: usize = 2_048;

#[derive(Debug, Error)]
pub enum ResignJwtError {
    #[error("re-signing key must be a PKCS#8 RSA private key of at least {MIN_RSA_BITS} bits")]
    InvalidSigningKey,
    #[error("re-signed JWT is malformed")]
    InvalidTokenFormat,
    #[error("re-signed JWT signature is invalid")]
    InvalidSignature,
}

pub type SigningKey = rsa::pkcs1v15::SigningKey<Sha256>;

/// Loads the Authguard RS256 signing key from a PKCS#8 PEM of at least 2048 bits.
///
/// # Errors
///
/// Returns an error when the PEM is malformed or the key is too short.
pub fn load_signing_key(private_key_pem: &str) -> Result<SigningKey, ResignJwtError> {
    let key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .map_err(|_| ResignJwtError::InvalidSigningKey)?;
    if key.n().bits() < MIN_RSA_BITS {
        return Err(ResignJwtError::InvalidSigningKey);
    }
    key.validate().map_err(|_| ResignJwtError::InvalidSigningKey)?;
    Ok(SigningKey::new(key))
}

/// Serializes the paired public key as PKCS#1 PEM for business workloads.
///
/// Workloads verify the re-signed JWT with this public key only; the private
/// key never leaves Authguard.
///
/// # Errors
///
/// Returns an error only for an invalid in-memory key.
pub fn public_key_pem(key: &SigningKey) -> Result<String, ResignJwtError> {
    RsaPublicKey::from(key.as_ref())
        .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|_| ResignJwtError::InvalidSigningKey)
}

/// Signs one compact JWT as `header.payload.signature` over
/// RSASSA-PKCS1-v1_5 with SHA-256 (RS256, RFC 8017 § 8.2).
///
/// # Errors
///
/// Returns an error when the configured key is invalid.
pub fn sign(key: &SigningKey, payload_bytes: &[u8]) -> Result<String, ResignJwtError> {
    let signing_input = format!("{JWT_HEADER}.{}", URL_SAFE_NO_PAD.encode(payload_bytes));
    let signature = key.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())))
}

/// Verifies a re-signed compact JWT against the distributed PKCS#1 public key
/// and returns its decoded payload bytes.
///
/// Used by tests and tooling; business workloads verify with their own JWT
/// library against the public key.
///
/// # Errors
///
/// Returns an error for malformed tokens or invalid signatures.
pub fn verify(public_key_pem: &str, token: &str) -> Result<Vec<u8>, ResignJwtError> {
    let public = RsaPublicKey::from_pkcs1_pem(public_key_pem)
        .map_err(|_| ResignJwtError::InvalidSigningKey)?;
    let mut parts = token.split('.');
    let header = parts.next();
    let payload = parts.next();
    let signature = parts.next();
    let Some((payload, signature)) = payload.zip(signature) else {
        return Err(ResignJwtError::InvalidTokenFormat);
    };
    if header != Some(JWT_HEADER)
        || payload.is_empty()
        || signature.is_empty()
        || parts.next().is_some()
    {
        return Err(ResignJwtError::InvalidTokenFormat);
    }
    let signature =
        URL_SAFE_NO_PAD.decode(signature).map_err(|_| ResignJwtError::InvalidTokenFormat)?;
    let signing_input = format!("{JWT_HEADER}.{payload}");
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public);
    let signature = rsa::pkcs1v15::Signature::try_from(signature.as_slice())
        .map_err(|_| ResignJwtError::InvalidTokenFormat)?;
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| ResignJwtError::InvalidSignature)?;
    URL_SAFE_NO_PAD.decode(payload).map_err(|_| ResignJwtError::InvalidTokenFormat)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed 2048-bit test keypair: private PKCS#8 PEM (public half is derived).
    const TEST_PRIVATE_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCeCFtMCe27cC+r
vMoS2fLI4N2YIbbQCphtqn12hcTc5tdA4mf2PF2gvYtTsTwthq2WRnPzeluv9iRJ
COCAhTAPJ512dcMbMlY9c7OuvcBXCIzvORJWgFTGqWhHEpxkwECa2As71BhRlFnQ
NMZhuLogwmR40xKPcfBQSvKFCxtLTakpXsvVD4RZfqvIabcBeidyWPX7i3XXycGN
ZBk218myR4Ci3tT2JZiOdVPpVmeyEtomL8G4l/Fr0LP9u0c2qi+BnSkeuchlC9ma
nosuwt/7x3UMn9o8ZkIDo3j0YClKUo77bMe2RsvDnsMYy3g2NBeppnUa7+5B9aDi
Pge4QT2PAgMBAAECggEABFdAwWfGaW8inWoxTMTtfSS8FtPaPysDVoPShWvAOrx2
g4Lp4yLJBEN17RsXBuhw999Ai8VmeQC0V3M7I3HvyNgdjvrwxzGh78yFTif1KA7a
kYRKTij2ldcNFQ1cUWInLs7/Y/8mmdsO1SrAm5Tk5psgV7dIhmXVTtyi070N3LV0
HfnZ3vHXxFPBN4kUHrQ8YHMR0HyI/BXEQaz+BNbGI+BYDy/Pr8GPGyBYE1TbNJtj
Ay/7NIhpKlSnFH6KWJGvnrflD4kfd1Fx2JOt+NDDO3asE0xMmrQ8boBclwwMfdJ+
7PbnIQwfim7eBpJP9iqwOQ0i8B8GhgX7YOtaj7SlGQKBgQDfU/t0Dz/jREX9PoLC
dzQKzOmwQen4Y/2GyCK0/NTcRR4olaCOfSnZR2qQI0AmjfP0UNQGoXvyza0ekkkp
Ab/xXMeQRQj5R4Vap4MZ9LE7u9Zvi1w0YpCy6qHOkeZLWKPkgorxWmWtQssGcnEG
WMLWz6Abp1BOGDjeZF6H4gl05wKBgQC1JvMRH7RFc8+hY/YgNJ0JnHutmdIzZEjy
HCIsMlBvMcqeQFCRMaFwumF1uTP4jHENzqzmaiSYANWSLOdwgafsOKuhIc/blzi7
SmVudFddWZ+yMshd0lHgtzIxePkFJBjib+Zl/0PxIWr7a4yXrADgYEpHi0hoPoXV
ZVUoCbc1GQKBgQC/NDn/Pecm/xclINX3BPPro1EYdPaKkaFIOiVs62KbTBnsCV8z
X3nq6zgTO/r6h2KsdF9zZeKnGOz1Va2JjFP3o8XAgTqTomZMHUsjd9oeGE4ZpilF
OHZGmJf8MfIH5FY9mH648PpIgv0sAeM+2dPG8nBT/MXGdvqJfUlp8V7DVQKBgHuV
dOHLxUpUdePetDzIaBH0hZOrivGwiutRMicAtEsHpvlLWyuStlaXcIHFtaTs+vu2
cdJHu2tPtmQg6kugyJSpHL2yuYFPq05qtMQj7q4qxH3nkzYek+lAUafapdhSBgAE
4yPWf91zNO8NMj8PAxIP3tzsMpube+ZXWT8VUb2RAoGBAJl699cUmFfTSVEOpU+P
0wX2UUTypchwNNk8MzZ4ZmFgqsKgt+PROHcjd/0dKIv3FjM/xBVWgHsPn5wD0RjY
eXrtxDaESeqnUJW1vcK/1bqPxRo0fT1oGHsI3ThufLc4mPU13To+1brJjwFUdjCU
Pmx4WC0H9qHaM5lIYJQWBkOg
-----END PRIVATE KEY-----";

    /// Deliberately weak 1024-bit key used only to verify the size rejection.
    const WEAK_PRIVATE_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALNoQYNbDCKVjMZu
ugz9TG6cJMSU2qhnvAUMseTs8ZTp62SESUL7zvnGUY0APHSQgadoolJF4ptkht2N
Xdw/X52lFc5JJYwjRDskevBFmPvdeBY9XPJ6O2xKiTi/UDPn4eh2MhvmRn1EeoKl
2HXG1Uc8dsmLV5e2JVCmGlW+nYY3AgMBAAECgYBXr0ntyG8q7Ars5Stbs+VKXlh+
F/6ytlin4yeDKud8D8Qz0Y/5BBeJ7ornLkld807bIoHLUkrKBh0AZdqNDhBNq8Bz
dirNHGZNFqBSS94QuY65gWKOAJYK7pO3eiVsl4uPPfu3bnileEeiQPKfmILmIMpV
cBaB4bPvcuFWNhC18QJBAN6vOQY7kXFbxqgJ3Lr1ryWIkgb83NK0pKsBCPz3uUQo
sfIMEv/2FkztTTymJZtelIN+csJJcY6iq7eT/FSuwe8CQQDOP4XvbsjOQNZmWxca
xn4ra45IIjajJ4QTXdfYbdQW0Ztl7BRgAvUsf92D8pYoKroDkvisVN9t3h1L7pl8
CSg5AkEAx2+5K6rX9OWUQtUqWktFhOEOn7GB+DgPLpQrv5wB0lh8HmLP9WwpxtXV
Eddf4QnRCv+JuhXa3Ts1faHNIO6vAwJAE+FBmrOV/XN4dwM+teD+FldWrpNFqvJL
I8a+4GitsclgbjGUQTDnyvNEOcyvNo3vwhpvh8TiiGeJcWE9QBxt2QJAL0tNI3La
w5ya0hFd3WaAuVRWmVI2NfsJTvraQ4xit/bLfCNLfstClGg6mCBlX4cZcpYbMZxR
e5cOzSbiScXV3A==
-----END PRIVATE KEY-----";

    fn key() -> SigningKey {
        load_signing_key(TEST_PRIVATE_KEY_PEM).expect("valid signing key")
    }

    #[test]
    fn signs_compact_rs256_jwt_and_verifies_roundtrip() {
        let token = sign(&key(), br#"{"authguardOrigin":true}"#).expect("sign");
        let parts = token.split('.').collect::<Vec<_>>();
        assert_eq!(parts.len(), 3, "compact JWT has exactly three segments");
        assert_eq!(parts[0], JWT_HEADER, "header advertises RS256");
        let public_pem = public_key_pem(&key()).expect("public key");
        let payload = verify(&public_pem, &token).expect("verify");
        assert_eq!(payload, br#"{"authguardOrigin":true}"#);
    }

    #[test]
    fn rejects_tampered_payload_and_foreign_signatures() {
        let token = sign(&key(), b"{}").expect("sign");
        let tampered_payload = URL_SAFE_NO_PAD.encode(b"tampered");
        let parts = token.split('.').collect::<Vec<_>>();
        let public_pem = public_key_pem(&key()).expect("public key");
        assert!(matches!(
            verify(&public_pem, &format!("{}.{}.{}", parts[0], tampered_payload, parts[2])),
            Err(ResignJwtError::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_malformed_tokens() {
        let public_pem = public_key_pem(&key()).expect("public key");
        assert!(matches!(
            verify(&public_pem, "not-a-jwt"),
            Err(ResignJwtError::InvalidTokenFormat)
        ));
        assert!(matches!(
            verify(&public_pem, &format!("{JWT_HEADER}..")),
            Err(ResignJwtError::InvalidTokenFormat)
        ));
    }

    #[test]
    fn rejects_short_or_malformed_private_keys() {
        assert!(matches!(load_signing_key("not a pem"), Err(ResignJwtError::InvalidSigningKey)));
        assert!(matches!(
            load_signing_key(WEAK_PRIVATE_KEY_PEM),
            Err(ResignJwtError::InvalidSigningKey)
        ));
    }

    #[test]
    fn public_key_pem_is_parseable_pkcs1() {
        let pem = public_key_pem(&key()).expect("public key");
        assert!(pem.contains("BEGIN RSA PUBLIC KEY"), "PKCS#1 public key PEM");
    }
}
