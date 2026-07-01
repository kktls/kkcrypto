//! IPsec and IKEv2 Cryptographic Suites.

use crate::{
    error::Result,
    markers,
};

/// IPsec Suite B Cryptographic Suite (RFC 6379) - 128-bit security.
///
/// Defined in [RFC 6379](https://datatracker.ietf.org/doc/html/rfc6379).
pub trait IpsecSuiteB128: markers::Combo {
    /// Derives keying material using IKEv2 PRF (HMAC-SHA-256).
    fn ikev2_prf(key: &[u8], data: &[u8], out: &mut [u8]) -> Result<()>;
    /// Encrypts an ESP packet using AES-128-GCM.
    fn esp_encrypt(key: &[u8; 16], iv: &[u8; 8], pt: &[u8], ct: &mut [u8], tag: &mut [u8; 16]) -> Result<()>;
    /// Decrypts an ESP packet using AES-128-GCM.
    fn esp_decrypt(key: &[u8; 16], iv: &[u8; 8], ct: &[u8], tag: &[u8; 16], pt: &mut [u8]) -> Result<()>;
    /// Verifies authentication signatures using ECDSA P-256.
    fn verify_auth(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()>;
}

/// IPsec Suite B Cryptographic Suite (RFC 6379) - 256-bit security.
///
/// Defined in [RFC 6379](https://datatracker.ietf.org/doc/html/rfc6379).
pub trait IpsecSuiteB256: markers::Combo {
    fn ikev2_prf(key: &[u8], data: &[u8], out: &mut [u8]) -> Result<()>;
    fn esp_encrypt(key: &[u8; 32], iv: &[u8; 8], pt: &[u8], ct: &mut [u8], tag: &mut [u8; 16]) -> Result<()>;
    fn esp_decrypt(key: &[u8; 32], iv: &[u8; 8], ct: &[u8], tag: &[u8; 16], pt: &mut [u8]) -> Result<()>;
    fn verify_auth(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()>;
}

/// VPN Standard Suite (Commercial Grade).
///
/// Legacy VPN compatibility suite utilizing AES-256-CBC and HMAC-SHA256.
pub trait IpsecLegacyVpnStandard: markers::Combo {
    fn ikev2_prf(key: &[u8], data: &[u8], out: &mut [u8]) -> Result<()>;
    /// Encrypts an ESP packet using AES-256-CBC and tags it with HMAC-SHA256.
    fn esp_encrypt_cbc_hmac(
        key_enc: &[u8; 32],
        key_mac: &[u8; 32],
        iv: &[u8; 16],
        pt: &[u8],
        ct: &mut [u8],
        mac: &mut [u8; 32],
    ) -> Result<()>;
    /// Decrypts an ESP packet using AES-256-CBC and verifies HMAC-SHA256.
    fn esp_decrypt_cbc_hmac(
        key_enc: &[u8; 32],
        key_mac: &[u8; 32],
        iv: &[u8; 16],
        ct: &[u8],
        mac: &[u8; 32],
        pt: &mut [u8],
    ) -> Result<()>;
    /// Verifies RSA-2048 signatures for IKEv2 authentication.
    fn verify_auth_rsa(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()>;
}
