//! Camellia Block Cipher (Japanese Standard).

use crate::{
    base,
    markers,
};

/// Camellia-128 block cipher.
///
/// Defined in [RFC 3713](https://datatracker.ietf.org/doc/html/rfc3713).
pub trait Camellia128: base::KeyInit<16> + base::BlockCipher<16> + markers::Symmetric + markers::BlockCipher {}

/// Camellia-192 block cipher.
///
/// Defined in [RFC 3713](https://datatracker.ietf.org/doc/html/rfc3713).
pub trait Camellia192: base::KeyInit<24> + base::BlockCipher<16> + markers::Symmetric + markers::BlockCipher {}

/// Camellia-256 block cipher.
///
/// Defined in [RFC 3713](https://datatracker.ietf.org/doc/html/rfc3713).
pub trait Camellia256: base::KeyInit<32> + base::BlockCipher<16> + markers::Symmetric + markers::BlockCipher {}
