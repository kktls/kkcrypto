//! Camellia Block Cipher (Japanese Standard).

use crate::{
    base,
    markers,
};

/// Length of a Camellia block in bytes (128 bits).
pub const CAMELLIA_BLOCK_LEN: usize = 16;

/// Length of a Camellia-128 key in bytes (128 bits).
pub const CAMELLIA128_KEY_LEN: usize = 16;
/// Length of a Camellia-192 key in bytes (192 bits).
pub const CAMELLIA192_KEY_LEN: usize = 24;
/// Length of a Camellia-256 key in bytes (256 bits).
pub const CAMELLIA256_KEY_LEN: usize = 32;

/// Camellia-128 block cipher.
///
/// Defined in [RFC 3713](https://datatracker.ietf.org/doc/html/rfc3713).
pub trait Camellia128:
    base::KeyInit<CAMELLIA128_KEY_LEN> + base::BlockCipher<CAMELLIA_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}

/// Camellia-192 block cipher.
///
/// Defined in [RFC 3713](https://datatracker.ietf.org/doc/html/rfc3713).
pub trait Camellia192:
    base::KeyInit<CAMELLIA192_KEY_LEN> + base::BlockCipher<CAMELLIA_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}

/// Camellia-256 block cipher.
///
/// Defined in [RFC 3713](https://datatracker.ietf.org/doc/html/rfc3713).
pub trait Camellia256:
    base::KeyInit<CAMELLIA256_KEY_LEN> + base::BlockCipher<CAMELLIA_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}
