//! FIDO2 and WebAuthn specific combinations.

use alloc::vec::Vec;

use crate::{
    error::Result,
    markers,
};

/// FIDO2 ES256 (ECDSA P-256 + SHA-256).
///
/// Defined in [WebAuthn W3C Recommendation](https://www.w3.org/TR/webauthn-2/).
pub trait FidoEs256: markers::Combo {
    /// Signs the combined authenticator data and client data hash.
    fn sign(sk: &[u8], auth_data: &[u8], client_data_hash: &[u8; 32]) -> Result<Vec<u8>>;
    /// Verifies the FIDO2 ES256 signature.
    fn verify(pk: &[u8], auth_data: &[u8], client_data_hash: &[u8; 32], sig: &[u8]) -> Result<()>;
}

/// FIDO2 EdDSA (Ed25519).
///
/// Defined in [WebAuthn W3C Recommendation](https://www.w3.org/TR/webauthn-2/).
pub trait FidoEdDsa: markers::Combo {
    /// Signs the combined authenticator data and client data hash using
    /// Ed25519.
    fn sign(sk: &[u8; 64], auth_data: &[u8], client_data_hash: &[u8; 32]) -> Result<Vec<u8>>;
    /// Verifies the FIDO2 Ed25519 signature.
    fn verify(pk: &[u8; 32], auth_data: &[u8], client_data_hash: &[u8; 32], sig: &[u8]) -> Result<()>;
}
