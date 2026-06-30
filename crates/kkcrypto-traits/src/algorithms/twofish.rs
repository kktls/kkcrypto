//! Twofish Block Cipher (AES Finalist).

use crate::{
    base,
    markers,
};

/// Twofish-128 block cipher.
///
/// Defined in the [Twofish Specification](https://www.schneier.com/academic/twofish/).
pub trait Twofish128: base::KeyInit<16> + base::BlockCipher<16> + markers::Symmetric + markers::BlockCipher {}

/// Twofish-192 block cipher.
///
/// Defined in the [Twofish Specification](https://www.schneier.com/academic/twofish/).
pub trait Twofish192: base::KeyInit<24> + base::BlockCipher<16> + markers::Symmetric + markers::BlockCipher {}

/// Twofish-256 block cipher.
///
/// Defined in the [Twofish Specification](https://www.schneier.com/academic/twofish/).
pub trait Twofish256: base::KeyInit<32> + base::BlockCipher<16> + markers::Symmetric + markers::BlockCipher {}
