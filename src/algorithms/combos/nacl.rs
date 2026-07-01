//! Networking and Cryptography library (NaCl) / Libsodium constructions.

use crate::{
    error::Result,
    markers,
};

/// NaCl `crypto_secretbox`
///
/// Defined in the [NaCl Cryptography Library](https://nacl.cr.yp.to/secretbox.html).
pub trait NaclSecretBox: markers::Combo {
    /// Authenticates and encrypts a message using XSalsa20-Poly1305.
    fn secretbox(msg: &[u8], nonce: &[u8; 24], key: &[u8; 32], out: &mut [u8]) -> Result<()>;
    /// Verifies and decrypts a ciphertext using XSalsa20-Poly1305.
    fn secretbox_open(ct: &[u8], nonce: &[u8; 24], key: &[u8; 32], out: &mut [u8]) -> Result<()>;
}

/// NaCl `crypto_box`
///
/// Defined in the [NaCl Cryptography Library](https://nacl.cr.yp.to/box.html).
pub trait NaclBox: markers::Combo {
    /// Performs public-key authenticated encryption.
    fn box_(msg: &[u8], nonce: &[u8; 24], pk: &[u8; 32], sk: &[u8; 32], out: &mut [u8]) -> Result<()>;
    /// Performs public-key verified decryption.
    fn box_open(ct: &[u8], nonce: &[u8; 24], pk: &[u8; 32], sk: &[u8; 32], out: &mut [u8]) -> Result<()>;
}

/// NaCl `crypto_sign`
///
/// Defined in the [NaCl Cryptography Library](https://nacl.cr.yp.to/sign.html).
pub trait NaclSign: markers::Combo {
    /// Signs a message using Ed25519 and prepends the signature (attached API).
    fn sign(msg: &[u8], sk: &[u8; 64], out: &mut [u8]) -> Result<()>;
    /// Verifies a signed message using Ed25519 and recovers the plaintext.
    fn sign_open(signed_msg: &[u8], pk: &[u8; 32], out: &mut [u8]) -> Result<()>;
}
