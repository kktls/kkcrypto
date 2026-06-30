//! Serpent Block Cipher (AES Finalist).

use crate::{
    base,
    markers,
};

/// Length of a Serpent block in bytes (128 bits).
pub const SERPENT_BLOCK_LEN: usize = 16;

/// Length of a Serpent-128 key in bytes (128 bits).
pub const SERPENT128_KEY_LEN: usize = 16;
/// Length of a Serpent-192 key in bytes (192 bits).
pub const SERPENT192_KEY_LEN: usize = 24;
/// Length of a Serpent-256 key in bytes (256 bits).
pub const SERPENT256_KEY_LEN: usize = 32;

/// Serpent-128 block cipher.
///
/// Defined in the [Serpent Specification](https://www.cl.cam.ac.uk/~rja14/serpent.html).
pub trait Serpent128:
    base::KeyInit<SERPENT128_KEY_LEN> + base::BlockCipher<SERPENT_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}

/// Serpent-192 block cipher.
///
/// Defined in the [Serpent Specification](https://www.cl.cam.ac.uk/~rja14/serpent.html).
pub trait Serpent192:
    base::KeyInit<SERPENT192_KEY_LEN> + base::BlockCipher<SERPENT_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}

/// Serpent-256 block cipher.
///
/// Defined in the [Serpent Specification](https://www.cl.cam.ac.uk/~rja14/serpent.html).
pub trait Serpent256:
    base::KeyInit<SERPENT256_KEY_LEN> + base::BlockCipher<SERPENT_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}
