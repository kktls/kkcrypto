//! BLAKE2 and BLAKE3 hash functions.

use crate::{
    base,
    markers,
};

/// BLAKE2s (32-byte output).
///
/// Defined in [RFC 7693](https://datatracker.ietf.org/doc/html/rfc7693).
pub trait Blake2s: base::Digest<32> + markers::Hash {}

/// BLAKE2b (64-byte output).
///
/// Defined in [RFC 7693](https://datatracker.ietf.org/doc/html/rfc7693).
pub trait Blake2b: base::Digest<64> + markers::Hash {}

/// BLAKE3 cryptographic hash and Extendable-Output Function.
///
/// Defined in the [BLAKE3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf).
pub trait Blake3: base::Digest<32> + base::Xof + markers::Hash {}
