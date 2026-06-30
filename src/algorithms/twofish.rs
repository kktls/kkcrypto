//! Twofish Block Cipher (AES Finalist).

use crate::{
    base,
    markers,
};

/// Length of a Twofish block in bytes (128 bits).
pub const TWOFISH_BLOCK_LEN: usize = 16;

/// Length of a Twofish-128 key in bytes (128 bits).
pub const TWOFISH128_KEY_LEN: usize = 16;
/// Length of a Twofish-192 key in bytes (192 bits).
pub const TWOFISH192_KEY_LEN: usize = 24;
/// Length of a Twofish-256 key in bytes (256 bits).
pub const TWOFISH256_KEY_LEN: usize = 32;

/// Twofish-128 block cipher.
///
/// Defined in the [Twofish Specification](https://www.schneier.com/academic/twofish/).
pub trait Twofish128:
    base::KeyInit<TWOFISH128_KEY_LEN> + base::BlockCipher<TWOFISH_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}

/// Twofish-192 block cipher.
///
/// Defined in the [Twofish Specification](https://www.schneier.com/academic/twofish/).
pub trait Twofish192:
    base::KeyInit<TWOFISH192_KEY_LEN> + base::BlockCipher<TWOFISH_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}

/// Twofish-256 block cipher.
///
/// Defined in the [Twofish Specification](https://www.schneier.com/academic/twofish/).
pub trait Twofish256:
    base::KeyInit<TWOFISH256_KEY_LEN> + base::BlockCipher<TWOFISH_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}
