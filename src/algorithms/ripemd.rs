//! RIPEMD cryptographic hash functions.

use crate::{
    base,
    markers,
};

/// Output length for RIPEMD-128 in bytes (128 bits).
pub const RIPEMD128_OUT_LEN: usize = 16;

/// Output length for RIPEMD-160 in bytes (160 bits).
pub const RIPEMD160_OUT_LEN: usize = 20;

/// RIPEMD-128 hash function.
///
/// Defined in [ISO/IEC 10118-3:2018](https://www.iso.org/standard/67909.html).
pub trait Ripemd128: base::Digest<RIPEMD128_OUT_LEN> + markers::Hash {}

/// RIPEMD-160 hash function.
///
/// Defined in [ISO/IEC 10118-3:2018](https://www.iso.org/standard/67909.html).
pub trait Ripemd160: base::Digest<RIPEMD160_OUT_LEN> + markers::Hash {}