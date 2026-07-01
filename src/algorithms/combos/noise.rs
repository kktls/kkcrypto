//! Noise Protocol Framework specific instantiations.

use alloc::vec::Vec;

use crate::{
    error::Result,
    markers,
};

/// `Noise_IK_25519_ChaChaPoly_BLAKE2s`
///
/// The Noise protocol instantiation utilized by WireGuard.
/// Defined in [WireGuard Protocol](https://www.wireguard.com/papers/wireguard.pdf).
pub trait NoiseIk25519ChaChaPolyBlake2s: markers::Combo {
    /// Processes the IK initiation payload and returns the handshake outputs.
    fn initialize_handshake(s: &[u8; 32], rs: &[u8; 32], payload: &[u8]) -> Result<(Vec<u8>, [u8; 32], [u8; 32])>; // msg, tk, rk
    /// Encrypts a transport payload during the transport phase.
    fn encrypt_payload(k: &[u8; 32], n: u64, pt: &[u8]) -> Result<Vec<u8>>;
    /// Decrypts a transport payload during the transport phase.
    fn decrypt_payload(k: &[u8; 32], n: u64, ct: &[u8]) -> Result<Vec<u8>>;
}

/// `Noise_XX_25519_AESGCM_SHA256`
///
/// Standard interactive Noise XX pattern (Lightning Network variant).
/// Defined in [Noise Protocol Framework](https://noiseprotocol.org/noise.html).
pub trait NoiseXx25519AesGcmSha256: markers::Combo {
    /// Mixes Diffie-Hellman parameters into the Noise symmetric state.
    fn mix_dh(state: &mut [u8; 32], dh_out: &[u8; 32]) -> Result<()>;
    /// Encrypts and writes a handshake message.
    fn encrypt_and_hash(state: &mut [u8; 32], key: Option<&[u8; 32]>, nonce: u64, pt: &[u8]) -> Result<Vec<u8>>;
    /// Decrypts and reads a handshake message.
    fn decrypt_and_hash(state: &mut [u8; 32], key: Option<&[u8; 32]>, nonce: u64, ct: &[u8]) -> Result<Vec<u8>>;
}
