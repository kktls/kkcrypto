//! OpenPGP (RFC 4880 / RFC 9580) combined constructions.

use alloc::vec::Vec;

use crate::{
    error::Result,
    markers,
};

/// OpenPGP v4 Legacy RSA
///
/// Defined in [RFC 4880](https://datatracker.ietf.org/doc/html/rfc4880).
pub trait OpenPgpV4RsaRsa: markers::Combo {
    /// Generates a v4 RSA signature packet over a hashed payload.
    fn sign_packet(sk: &[u8], hash: &[u8]) -> Result<Vec<u8>>;
    /// Encrypts an OpenPGP session key using RSA.
    fn encrypt_session_key(pk: &[u8], session_key: &[u8]) -> Result<Vec<u8>>;
    /// Encrypts data using AES-256-CFB (OpenPGP specific CFB mode).
    fn encrypt_data_cfb(session_key: &[u8; 32], pt: &[u8]) -> Result<Vec<u8>>;
}

/// OpenPGP v4/v5 ECC (Ed25519 + Cv25519)
///
/// Defined in [RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580).
pub trait OpenPgpEcc25519: markers::Combo {
    /// Generates an Ed25519 signature packet.
    fn sign_packet(sk: &[u8; 64], hash: &[u8]) -> Result<Vec<u8>>;
    /// Encrypts a session key using Cv25519 (ECDH over X25519 wrapped via KDF).
    fn encrypt_session_key(pk: &[u8; 32], session_key: &[u8]) -> Result<Vec<u8>>;
    /// Encrypts data using AES-256-OCB or CFB.
    fn encrypt_data_ocb(session_key: &[u8; 32], pt: &[u8]) -> Result<Vec<u8>>;
}
