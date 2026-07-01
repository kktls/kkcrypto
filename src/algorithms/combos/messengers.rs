//! Encrypted messenger protocol combinations.

use alloc::vec::Vec;

use crate::{
    error::Result,
    markers,
};

// ==========================================
// Signal Protocol
// ==========================================

/// Signal Protocol: X3DH (Extended Triple Diffie-Hellman)
///
/// Defined in [X3DH Specification](https://signal.org/docs/specifications/x3dh/).
pub trait SignalX3dh: markers::Combo {
    /// Computes the X3DH shared secret key material (SK) from DH parameters.
    fn compute_sk(
        ik_a: &[u8; 32],
        ek_a: &[u8; 32],
        ik_b: &[u8; 32],
        spk_b: &[u8; 32],
        opk_b: Option<&[u8; 32]>,
    ) -> Result<[u8; 32]>;
}

/// Signal Protocol: Double Ratchet
///
/// Defined in [Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/).
pub trait SignalDoubleRatchet: markers::Combo {
    /// Performs a Diffie-Hellman ratchet step, returning a new Root Key and
    /// Chain Key.
    fn dh_ratchet(rk: &[u8; 32], dh_out: &[u8; 32]) -> Result<([u8; 32], [u8; 32])>;
    /// Performs a symmetric-key ratchet step, returning a new Chain Key and
    /// Message Key.
    fn sym_ratchet(ck: &[u8; 32]) -> Result<([u8; 32], [u8; 32])>;
    /// Encrypts a message using a derived Message Key (AES-256-CBC +
    /// HMAC-SHA256).
    fn encrypt_message(mk: &[u8; 32], pt: &[u8]) -> Result<Vec<u8>>;
    /// Decrypts a message using a derived Message Key.
    fn decrypt_message(mk: &[u8; 32], ct: &[u8]) -> Result<Vec<u8>>;
}

// ==========================================
// Telegram MTProto
// ==========================================

/// Telegram MTProto v2.0 Symmetric Encryption
///
/// Defined in [Telegram Core API](https://core.telegram.org/mtproto).
pub trait MtProtoAes256IgeSha256: markers::Combo {
    /// Encrypts payload using AES-256-IGE.
    fn encrypt_ige(key: &[u8; 32], iv: &[u8; 32], pt: &[u8]) -> Result<Vec<u8>>;
    /// Decrypts payload using AES-256-IGE.
    fn decrypt_ige(key: &[u8; 32], iv: &[u8; 32], ct: &[u8]) -> Result<Vec<u8>>;
}

// ==========================================
// SimpleX Chat
// ==========================================

/// SimpleX Messaging Protocol (SMP) Transport Encryption.
///
/// Defined in [SimpleX Specifications](https://github.com/simplex-chat/simplexmq).
pub trait SimpleXTransportNacl: markers::Combo {
    fn encrypt_transport(key: &[u8; 32], nonce: &[u8; 24], pt: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_transport(key: &[u8; 32], nonce: &[u8; 24], ct: &[u8]) -> Result<Vec<u8>>;
}
