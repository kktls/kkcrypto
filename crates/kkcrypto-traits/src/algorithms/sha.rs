//! Secure Hash Algorithms (SHA-1, SHA-2, SHA-3) and XOFs.

use crate::{
    base,
    markers,
};

/// SHA-1 hash function.
///
/// Defined in [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
pub trait Sha1: base::Digest<20> + markers::Hash {}

/// SHA-256 hash function.
///
/// Defined in [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
pub trait Sha256: base::Digest<32> + markers::Hash {}

/// SHA-384 hash function.
///
/// Defined in [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
pub trait Sha384: base::Digest<48> + markers::Hash {}

/// SHA-512 hash function.
///
/// Defined in [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
pub trait Sha512: base::Digest<64> + markers::Hash {}

/// SHAKE-128 Extendable-Output Function.
///
/// Defined in [NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final).
pub trait Shake128: base::Xof + markers::Hash {}
