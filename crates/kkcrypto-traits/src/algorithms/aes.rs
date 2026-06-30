//! Advanced Encryption Standard (AES) primitives.

use crate::{
    base,
    markers,
};

/// Length of an AES block in bytes (128 bits).
pub const AES_BLOCK_LEN: usize = 16;

/// Length of an AES-128 key in bytes (128 bits).
pub const AES128_KEY_LEN: usize = 16;
/// Length of an AES-192 key in bytes (192 bits).
pub const AES192_KEY_LEN: usize = 24;
/// Length of an AES-256 key in bytes (256 bits).
pub const AES256_KEY_LEN: usize = 32;

/// Standard nonce length for GCM and GCM-SIV modes in bytes (96 bits).
pub const GCM_STANDARD_NONCE_LEN: usize = 12;
/// Standard authentication tag length for GCM and GCM-SIV modes in bytes (128
/// bits).
pub const GCM_STANDARD_TAG_LEN: usize = 16;

/// Standard nonce length for CCM mode in bytes (96 bits).
pub const CCM_STANDARD_NONCE_LEN: usize = 12;

/// AES-128 raw block cipher.
///
/// Defined in [NIST FIPS 197](https://csrc.nist.gov/pubs/fips/197/final).
pub trait Aes128:
    base::KeyInit<AES128_KEY_LEN> + base::BlockCipher<AES_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}

/// AES-192 raw block cipher.
///
/// Defined in [NIST FIPS 197](https://csrc.nist.gov/pubs/fips/197/final).
pub trait Aes192:
    base::KeyInit<AES192_KEY_LEN> + base::BlockCipher<AES_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}

/// AES-256 raw block cipher.
///
/// Defined in [NIST FIPS 197](https://csrc.nist.gov/pubs/fips/197/final).
pub trait Aes256:
    base::KeyInit<AES256_KEY_LEN> + base::BlockCipher<AES_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}

/// AES-128 in Galois/Counter Mode (GCM).
///
/// Defined in [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).
pub trait Aes128Gcm:
    base::KeyInit<AES128_KEY_LEN>
    + base::Aead<GCM_STANDARD_NONCE_LEN, GCM_STANDARD_TAG_LEN>
    + markers::Symmetric
    + markers::Aead
{
}

/// AES-192 in Galois/Counter Mode (GCM).
///
/// Defined in [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).
pub trait Aes192Gcm:
    base::KeyInit<AES192_KEY_LEN>
    + base::Aead<GCM_STANDARD_NONCE_LEN, GCM_STANDARD_TAG_LEN>
    + markers::Symmetric
    + markers::Aead
{
}

/// AES-256 in Galois/Counter Mode (GCM).
///
/// Defined in [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).
pub trait Aes256Gcm:
    base::KeyInit<AES256_KEY_LEN>
    + base::Aead<GCM_STANDARD_NONCE_LEN, GCM_STANDARD_TAG_LEN>
    + markers::Symmetric
    + markers::Aead
{
}

/// AES-128 in GCM-SIV mode (Nonce mis-use resistance).
///
/// Defined in [RFC 8452](https://datatracker.ietf.org/doc/html/rfc8452).
pub trait Aes128GcmSiv:
    base::KeyInit<AES128_KEY_LEN>
    + base::Aead<GCM_STANDARD_NONCE_LEN, GCM_STANDARD_TAG_LEN>
    + markers::Symmetric
    + markers::Aead
{
}

/// AES-256 in GCM-SIV mode (Nonce mis-use resistance).
///
/// Defined in [RFC 8452](https://datatracker.ietf.org/doc/html/rfc8452).
pub trait Aes256GcmSiv:
    base::KeyInit<AES256_KEY_LEN>
    + base::Aead<GCM_STANDARD_NONCE_LEN, GCM_STANDARD_TAG_LEN>
    + markers::Symmetric
    + markers::Aead
{
}

/// AES-128 in Cipher Block Chaining (CBC) mode.
///
/// Defined in [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).
pub trait Aes128Cbc:
    base::KeyInit<AES128_KEY_LEN> + base::Cbc<AES_BLOCK_LEN> + markers::Symmetric + markers::Cbc
{
}

/// AES-256 in Cipher Block Chaining (CBC) mode.
///
/// Defined in [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).
pub trait Aes256Cbc:
    base::KeyInit<AES256_KEY_LEN> + base::Cbc<AES_BLOCK_LEN> + markers::Symmetric + markers::Cbc
{
}

/// AES-128 in Counter with CBC-MAC (CCM) mode.
///
/// Defined in [NIST SP 800-38C](https://csrc.nist.gov/pubs/sp/800/38/c/final).
pub trait Aes128Ccm:
    base::KeyInit<AES128_KEY_LEN>
    + base::Aead<CCM_STANDARD_NONCE_LEN, GCM_STANDARD_TAG_LEN>
    + markers::Symmetric
    + markers::Ccm
{
}
