//! ARIA Block Cipher (South Korean Standard).

use crate::{
    base,
    markers,
};

/// Length of an ARIA block in bytes (128 bits).
pub const ARIA_BLOCK_LEN: usize = 16;

/// Length of an ARIA-128 key in bytes (128 bits).
pub const ARIA128_KEY_LEN: usize = 16;
/// Length of an ARIA-192 key in bytes (192 bits).
pub const ARIA192_KEY_LEN: usize = 24;
/// Length of an ARIA-256 key in bytes (256 bits).
pub const ARIA256_KEY_LEN: usize = 32;

/// ARIA-128 block cipher.
///
/// Defined in [RFC 5794](https://datatracker.ietf.org/doc/html/rfc5794).
pub trait Aria128:
    base::KeyInit<ARIA128_KEY_LEN> + base::BlockCipher<ARIA_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}

/// ARIA-192 block cipher.
///
/// Defined in [RFC 5794](https://datatracker.ietf.org/doc/html/rfc5794).
pub trait Aria192:
    base::KeyInit<ARIA192_KEY_LEN> + base::BlockCipher<ARIA_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}

/// ARIA-256 block cipher.
///
/// Defined in [RFC 5794](https://datatracker.ietf.org/doc/html/rfc5794).
pub trait Aria256:
    base::KeyInit<ARIA256_KEY_LEN> + base::BlockCipher<ARIA_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}
