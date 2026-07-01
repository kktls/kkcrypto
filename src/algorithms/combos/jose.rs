//! JSON Web Signatures (JWS) and JSON Web Encryption (JWE) algorithms.

use alloc::vec::Vec;

use crate::{
    error::Result,
    markers,
};

// --- JWS Algorithms (RFC 7518) ---

/// JWS `RS256`: RSA PKCS#1 v1.5 with SHA-256.
/// Defined in [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518).
pub trait JwsRs256: markers::Combo {
    fn sign(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>>;
    fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()>;
}

/// JWS `PS256`: RSA PSS with SHA-256.
/// Defined in [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518).
pub trait JwsPs256: markers::Combo {
    fn sign(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>>;
    fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()>;
}

/// JWS `ES256`: ECDSA using P-256 and SHA-256.
/// Defined in [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518).
pub trait JwsEs256: markers::Combo {
    fn sign(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>>;
    fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()>;
}

/// JWS `EdDSA`: EdDSA signature using Ed25519.
/// Defined in [RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037).
pub trait JwsEdDsa: markers::Combo {
    fn sign(sk: &[u8; 64], msg: &[u8]) -> Result<Vec<u8>>;
    fn verify(pk: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<()>;
}

// --- JWE Algorithms (RFC 7518) ---

/// JWE `ECDH-ES+A128KW` with `A128GCM`.
/// Defined in [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518).
pub trait JweEcdhEsAes128KwAes128Gcm: markers::Combo {
    /// Performs ECDH key agreement and wraps the CEK.
    fn wrap_cek(peer_pk: &[u8], cek: &[u8; 16]) -> Result<Vec<u8>>;
    /// Unwraps the CEK using ECDH.
    fn unwrap_cek(local_sk: &[u8], wrapped_cek: &[u8]) -> Result<Vec<u8>>;
    /// Encrypts the JWE payload using AES-128-GCM.
    fn encrypt_payload(cek: &[u8; 16], iv: &[u8; 12], aad: &[u8], pt: &[u8]) -> Result<(Vec<u8>, [u8; 16])>; // returns (ct, tag)
}

/// JWE `RSA-OAEP-256` with `A256GCM`.
/// Defined in [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518).
pub trait JweRsaOaep256Aes256Gcm: markers::Combo {
    fn wrap_cek(peer_pk: &[u8], cek: &[u8; 32]) -> Result<Vec<u8>>;
    fn unwrap_cek(local_sk: &[u8], wrapped_cek: &[u8]) -> Result<Vec<u8>>;
    fn encrypt_payload(cek: &[u8; 32], iv: &[u8; 12], aad: &[u8], pt: &[u8]) -> Result<(Vec<u8>, [u8; 16])>;
}
