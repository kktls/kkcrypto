//! Message Authentication Codes (MACs).

use crate::{
    base,
    markers,
};

/// Output length for HMAC-MD5 in bytes (128 bits).
pub const HMAC_MD5_OUT_LEN: usize = 16;
/// Output length for HMAC-SHA1 in bytes (160 bits).
pub const HMAC_SHA1_OUT_LEN: usize = 20;
/// Output length for HMAC-SHA256 and HMAC-Streebog256 in bytes (256 bits).
pub const HMAC_SHA256_OUT_LEN: usize = 32;
/// Output length for HMAC-SHA384 in bytes (384 bits).
pub const HMAC_SHA384_OUT_LEN: usize = 48;
/// Output length for HMAC-SHA512 in bytes (512 bits).
pub const HMAC_SHA512_OUT_LEN: usize = 64;

/// Key length strictly required for Poly1305 in bytes (256 bits).
pub const POLY1305_KEY_LEN: usize = 32;
/// Output tag length for Poly1305 in bytes (128 bits).
pub const POLY1305_TAG_LEN: usize = 16;

/// Standard block/tag length for AES-based CMAC in bytes (128 bits).
pub const CMAC_AES_TAG_LEN: usize = 16;
/// Standard block/tag length for Triple-DES-based CMAC in bytes (64 bits).
pub const CMAC_TDES_TAG_LEN: usize = 8;

/// HMAC using MD5.
///
/// Defined in [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104).
pub trait HmacMd5:
    base::VariableKeyInit + base::Mac<HMAC_MD5_OUT_LEN> + markers::Symmetric + markers::Mac + markers::VariableLengthKey
{
}

/// HMAC using SHA-1.
///
/// Defined in [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104).
pub trait HmacSha1:
    base::VariableKeyInit + base::Mac<HMAC_SHA1_OUT_LEN> + markers::Symmetric + markers::Mac + markers::VariableLengthKey
{
}

/// HMAC using SHA-256. Accepts arbitrary length keys.
///
/// Defined in [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) and [FIPS 198-1](https://csrc.nist.gov/pubs/fips/198-1/final).
pub trait HmacSha256:
    base::VariableKeyInit + base::Mac<HMAC_SHA256_OUT_LEN> + markers::Symmetric + markers::Mac + markers::VariableLengthKey
{
}

/// HMAC using SHA-384.
///
/// Defined in [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104).
pub trait HmacSha384:
    base::VariableKeyInit + base::Mac<HMAC_SHA384_OUT_LEN> + markers::Symmetric + markers::Mac + markers::VariableLengthKey
{
}

/// HMAC using SHA-512. Accepts arbitrary length keys.
///
/// Defined in [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) and [FIPS 198-1](https://csrc.nist.gov/pubs/fips/198-1/final).
pub trait HmacSha512:
    base::VariableKeyInit + base::Mac<HMAC_SHA512_OUT_LEN> + markers::Symmetric + markers::Mac + markers::VariableLengthKey
{
}

/// HMAC using Streebog-256 (GOST standard).
///
/// Associated with [RFC 6986](https://datatracker.ietf.org/doc/html/rfc6986).
pub trait HmacStreebog256:
    base::VariableKeyInit + base::Mac<HMAC_SHA256_OUT_LEN> + markers::Symmetric + markers::Mac + markers::VariableLengthKey
{
}

/// Poly1305 MAC. Strictly requires a 32-byte (256-bit) key.
///
/// Defined in [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).
pub trait Poly1305:
    base::KeyInit<POLY1305_KEY_LEN> + base::Mac<POLY1305_TAG_LEN> + markers::Symmetric + markers::Mac
{
}

/// CMAC using AES-128.
///
/// Defined in [RFC 4493](https://datatracker.ietf.org/doc/html/rfc4493).
pub trait CmacAes128: base::KeyInit<16> + base::Mac<CMAC_AES_TAG_LEN> + markers::Symmetric + markers::Mac {}

/// CMAC using AES-192.
///
/// Defined in [RFC 4493](https://datatracker.ietf.org/doc/html/rfc4493).
pub trait CmacAes192: base::KeyInit<24> + base::Mac<CMAC_AES_TAG_LEN> + markers::Symmetric + markers::Mac {}

/// CMAC using AES-256.
///
/// Defined in [RFC 4493](https://datatracker.ietf.org/doc/html/rfc4493).
pub trait CmacAes256: base::KeyInit<32> + base::Mac<CMAC_AES_TAG_LEN> + markers::Symmetric + markers::Mac {}

/// CMAC using 3-key Triple DES (DES-EDE3).
pub trait CmacTdes: base::KeyInit<24> + base::Mac<CMAC_TDES_TAG_LEN> + markers::Symmetric + markers::Mac {}
