//! Secure Shell (SSH) specific constructions.

use alloc::vec::Vec;

use crate::{
    error::Result,
    markers,
};

/// `chacha20-poly1305@openssh.com`
///
/// Defined in [OpenSSH Specifications](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.chacha20poly1305).
pub trait OpenSshChaCha20Poly1305: markers::Combo {
    /// Encrypts an SSH packet using dual ChaCha20 states and Poly1305.
    fn encrypt_packet(k_main: &[u8; 32], k_header: &[u8; 32], seq: u32, pt: &[u8]) -> Result<Vec<u8>>;
    /// Decrypts an SSH packet encrypted via `chacha20-poly1305@openssh.com`.
    fn decrypt_packet(k_main: &[u8; 32], k_header: &[u8; 32], seq: u32, ct: &[u8]) -> Result<Vec<u8>>;
}

/// `aes128-gcm@openssh.com` / `aes256-gcm@openssh.com`
///
/// Defined in [RFC 5647](https://datatracker.ietf.org/doc/html/rfc5647).
pub trait OpenSshAesGcm: markers::Combo {
    /// Encrypts an SSH packet according to RFC 5647 format.
    fn encrypt_packet(key: &[u8], iv: &[u8; 12], seq: u32, pt: &[u8]) -> Result<Vec<u8>>;
    /// Decrypts an SSH packet according to RFC 5647 format.
    fn decrypt_packet(key: &[u8], iv: &[u8; 12], seq: u32, ct: &[u8]) -> Result<Vec<u8>>;
}

/// `curve25519-sha256`
///
/// Defined in [RFC 8731](https://datatracker.ietf.org/doc/html/rfc8731).
pub trait SshCurve25519Sha256: markers::Combo {
    /// Derives the exchange hash (H) and shared secret (K).
    fn kex_compute(local_sk: &[u8; 32], peer_pk: &[u8; 32], exchange_data: &[u8]) -> Result<(Vec<u8>, [u8; 32])>; // Returns (K, H)
}
