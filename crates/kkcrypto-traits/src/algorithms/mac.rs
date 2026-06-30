//! Message Authentication Codes (MACs).

use crate::{
    base,
    markers,
};

/// HMAC using MD5.
///
/// Defined in [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104).
pub trait HmacMd5:
    base::VariableKeyInit + base::Mac<16> + markers::Symmetric + markers::Mac + markers::VariableLengthKey
{
}

/// HMAC using SHA-1.
///
/// Defined in [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104).
pub trait HmacSha1:
    base::VariableKeyInit + base::Mac<20> + markers::Symmetric + markers::Mac + markers::VariableLengthKey
{
}

/// HMAC using SHA-256. Accepts arbitrary length keys.
///
/// Defined in [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) and [FIPS 198-1](https://csrc.nist.gov/pubs/fips/198-1/final).
pub trait HmacSha256:
    base::VariableKeyInit + base::Mac<32> + markers::Symmetric + markers::Mac + markers::VariableLengthKey
{
}

/// HMAC using SHA-384.
///
/// Defined in [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104).
pub trait HmacSha384:
    base::VariableKeyInit + base::Mac<48> + markers::Symmetric + markers::Mac + markers::VariableLengthKey
{
}

/// HMAC using SHA-512. Accepts arbitrary length keys.
///
/// Defined in [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) and [FIPS 198-1](https://csrc.nist.gov/pubs/fips/198-1/final).
pub trait HmacSha512:
    base::VariableKeyInit + base::Mac<64> + markers::Symmetric + markers::Mac + markers::VariableLengthKey
{
}

/// HMAC using Streebog-256 (GOST standard).
///
/// Associated with [RFC 6986](https://datatracker.ietf.org/doc/html/rfc6986).
pub trait HmacStreebog256:
    base::VariableKeyInit + base::Mac<32> + markers::Symmetric + markers::Mac + markers::VariableLengthKey
{
}

/// Poly1305 MAC. Strictly requires a 32-byte (256-bit) key.
///
/// Defined in [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).
pub trait Poly1305: base::KeyInit<32> + base::Mac<16> + markers::Symmetric + markers::Mac {}

/// CMAC using AES-128.
///
/// Defined in [RFC 4493](https://datatracker.ietf.org/doc/html/rfc4493).
pub trait CmacAes128: base::KeyInit<16> + base::Mac<16> + markers::Symmetric + markers::Mac {}
