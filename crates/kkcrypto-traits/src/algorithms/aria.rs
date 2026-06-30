//! ARIA Block Cipher (South Korean Standard).

use crate::{
    base,
    markers,
};

/// ARIA-128 block cipher.
///
/// Defined in [RFC 5794](https://datatracker.ietf.org/doc/html/rfc5794).
pub trait Aria128: base::KeyInit<16> + base::BlockCipher<16> + markers::Symmetric + markers::BlockCipher {}

/// ARIA-192 block cipher.
///
/// Defined in [RFC 5794](https://datatracker.ietf.org/doc/html/rfc5794).
pub trait Aria192: base::KeyInit<24> + base::BlockCipher<16> + markers::Symmetric + markers::BlockCipher {}

/// ARIA-256 block cipher.
///
/// Defined in [RFC 5794](https://datatracker.ietf.org/doc/html/rfc5794).
pub trait Aria256: base::KeyInit<32> + base::BlockCipher<16> + markers::Symmetric + markers::BlockCipher {}
