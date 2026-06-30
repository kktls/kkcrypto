//! BLAKE2 and BLAKE3 hash functions.

use crate::{
    base,
    markers,
};

/// Output length for BLAKE2s in bytes (256 bits).
pub const BLAKE2S_OUT_LEN: usize = 32;
/// Output length for BLAKE2b in bytes (512 bits).
pub const BLAKE2B_OUT_LEN: usize = 64;
/// Standard output length for BLAKE3 in bytes (256 bits).
pub const BLAKE3_OUT_LEN: usize = 32;

/// BLAKE2s (32-byte output).
///
/// Defined in [RFC 7693](https://datatracker.ietf.org/doc/html/rfc7693).
pub trait Blake2s: base::Digest<BLAKE2S_OUT_LEN> + markers::Hash {}

/// BLAKE2b (64-byte output).
///
/// Defined in [RFC 7693](https://datatracker.ietf.org/doc/html/rfc7693).
pub trait Blake2b: base::Digest<BLAKE2B_OUT_LEN> + markers::Hash {}

/// BLAKE3 cryptographic hash and Extendable-Output Function.
///
/// Defined in the [BLAKE3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf).
pub trait Blake3: base::Digest<BLAKE3_OUT_LEN> + base::Xof + markers::Hash {}
