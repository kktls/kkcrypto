//! Advanced Encryption Standard (AES) primitives.

use crate::{
    base,
    markers,
};

/// AES-128 raw block cipher.
///
/// Defined in [NIST FIPS 197](https://csrc.nist.gov/pubs/fips/197/final).
pub trait Aes128: base::KeyInit<16> + base::BlockCipher<16> + markers::Symmetric + markers::BlockCipher {}

/// AES-192 raw block cipher.
///
/// Defined in [NIST FIPS 197](https://csrc.nist.gov/pubs/fips/197/final).
pub trait Aes192: base::KeyInit<24> + base::BlockCipher<16> + markers::Symmetric + markers::BlockCipher {}

/// AES-256 raw block cipher.
///
/// Defined in [NIST FIPS 197](https://csrc.nist.gov/pubs/fips/197/final).
pub trait Aes256: base::KeyInit<32> + base::BlockCipher<16> + markers::Symmetric + markers::BlockCipher {}

/// AES-128 in Galois/Counter Mode (GCM).
///
/// Defined in [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).
pub trait Aes128Gcm: base::KeyInit<16> + base::Aead<12, 16> + markers::Symmetric + markers::Aead {}

/// AES-256 in Galois/Counter Mode (GCM).
///
/// Defined in [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).
pub trait Aes256Gcm: base::KeyInit<32> + base::Aead<12, 16> + markers::Symmetric + markers::Aead {}

/// AES-128 in Cipher Block Chaining (CBC) mode.
///
/// Defined in [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).
pub trait Aes128Cbc: base::KeyInit<16> + base::Cbc<16> + markers::Symmetric + markers::Cbc {}

/// AES-256 in Cipher Block Chaining (CBC) mode.
///
/// Defined in [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).
pub trait Aes256Cbc: base::KeyInit<32> + base::Cbc<16> + markers::Symmetric + markers::Cbc {}

/// AES-128 in Counter with CBC-MAC (CCM) mode.
///
/// Defined in [NIST SP 800-38C](https://csrc.nist.gov/pubs/sp/800/38/c/final).
pub trait Aes128Ccm: base::KeyInit<16> + base::Aead<12, 16> + markers::Symmetric + markers::Ccm {}
