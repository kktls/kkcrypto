//! Serpent Block Cipher (AES Finalist).

use crate::{
    base,
    markers,
};

/// Serpent-128 block cipher.
///
/// Defined in the [Serpent Specification](https://www.cl.cam.ac.uk/~rja14/serpent.html).
pub trait Serpent128: base::KeyInit<16> + base::BlockCipher<16> + markers::Symmetric + markers::BlockCipher {}

/// Serpent-192 block cipher.
///
/// Defined in the [Serpent Specification](https://www.cl.cam.ac.uk/~rja14/serpent.html).
pub trait Serpent192: base::KeyInit<24> + base::BlockCipher<16> + markers::Symmetric + markers::BlockCipher {}

/// Serpent-256 block cipher.
///
/// Defined in the [Serpent Specification](https://www.cl.cam.ac.uk/~rja14/serpent.html).
pub trait Serpent256: base::KeyInit<32> + base::BlockCipher<16> + markers::Symmetric + markers::BlockCipher {}
