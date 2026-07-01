//! Hybrid Public Key Encryption (HPKE) combinations.

use alloc::vec::Vec;

use crate::{
    error::Result,
    markers,
};

/// HPKE Base Mode: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM.
///
/// Defined in [RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180).
pub trait HpkeX25519HkdfSha256Aes128Gcm: markers::Combo {
    /// Encapsulates a shared secret and seals the plaintext payload in a single
    /// shot. Returns the encapsulated key (`enc`) and the ciphertext
    /// (`ct`).
    fn seal_base(pk_r: &[u8; 32], info: &[u8], aad: &[u8], pt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
    /// Decapsulates the shared secret and opens the ciphertext payload.
    fn open_base(enc: &[u8; 32], sk_r: &[u8; 32], info: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>>;
}

/// HPKE Base Mode: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 +
/// ChaCha20-Poly1305.
///
/// Defined in [RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180).
pub trait HpkeX25519HkdfSha256ChaCha20Poly1305: markers::Combo {
    fn seal_base(pk_r: &[u8; 32], info: &[u8], aad: &[u8], pt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
    fn open_base(enc: &[u8; 32], sk_r: &[u8; 32], info: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>>;
}

/// HPKE Base Mode: DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM.
///
/// Defined in [RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180).
pub trait HpkeP256HkdfSha256Aes128Gcm: markers::Combo {
    fn seal_base(pk_r: &[u8], info: &[u8], aad: &[u8], pt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
    fn open_base(enc: &[u8], sk_r: &[u8], info: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>>;
}
