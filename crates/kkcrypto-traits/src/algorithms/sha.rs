//! Secure Hash Algorithms (SHA-1, SHA-2, SHA-3) and XOFs.

use crate::{
    base,
    markers,
};

/// Output length for SHA-1 in bytes (160 bits).
pub const SHA1_OUT_LEN: usize = 20;
/// Output length for SHA-224 in bytes (224 bits).
pub const SHA224_OUT_LEN: usize = 28;
/// Output length for SHA-256 / SHA3-256 in bytes (256 bits).
pub const SHA256_OUT_LEN: usize = 32;
/// Output length for SHA-384 / SHA3-384 in bytes (384 bits).
pub const SHA384_OUT_LEN: usize = 48;
/// Output length for SHA-512 / SHA3-512 in bytes (512 bits).
pub const SHA512_OUT_LEN: usize = 64;

/// SHA-1 hash function.
///
/// Defined in [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
pub trait Sha1: base::Digest<SHA1_OUT_LEN> + markers::Hash {}

/// SHA-224 hash function.
///
/// Defined in [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
pub trait Sha224: base::Digest<SHA224_OUT_LEN> + markers::Hash {}

/// SHA-256 hash function.
///
/// Defined in [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
pub trait Sha256: base::Digest<SHA256_OUT_LEN> + markers::Hash {}

/// SHA-384 hash function.
///
/// Defined in [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
pub trait Sha384: base::Digest<SHA384_OUT_LEN> + markers::Hash {}

/// SHA-512 hash function.
///
/// Defined in [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
pub trait Sha512: base::Digest<SHA512_OUT_LEN> + markers::Hash {}

/// SHA3-256 hash function.
///
/// Defined in [NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final).
pub trait Sha3_256: base::Digest<SHA256_OUT_LEN> + markers::Hash {}

/// SHA3-384 hash function.
///
/// Defined in [NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final).
pub trait Sha3_384: base::Digest<SHA384_OUT_LEN> + markers::Hash {}

/// SHA3-512 hash function.
///
/// Defined in [NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final).
pub trait Sha3_512: base::Digest<SHA512_OUT_LEN> + markers::Hash {}

/// SHAKE-128 Extendable-Output Function.
///
/// Defined in [NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final).
pub trait Shake128: base::Xof + markers::Hash {}
