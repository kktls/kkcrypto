//! Russian National Standard (GOST) cryptography.

use crate::{
    base,
    markers,
};

/// Length of a GOST 28147-89 "Magma" block in bytes (64 bits).
pub const MAGMA_BLOCK_LEN: usize = 8;
/// Length of a GOST R 34.12-2015 "Kuznyechik" block in bytes (128 bits).
pub const KUZNYECHIK_BLOCK_LEN: usize = 16;

/// Length of keys for both Magma and Kuznyechik ciphers in bytes (256 bits).
pub const GOST_CIPHER_KEY_LEN: usize = 32;

/// Output length for Streebog-256 in bytes (256 bits).
pub const STREEBOG256_OUT_LEN: usize = 32;
/// Output length for Streebog-512 in bytes (512 bits).
pub const STREEBOG512_OUT_LEN: usize = 64;
/// Output length for the legacy GOST R 34.11-94 hash in bytes (256 bits).
pub const GOST94_OUT_LEN: usize = 32;

/// GOST 28147-89 / GOST R 34.12-2015 "Magma". (64-bit block, 256-bit key).
///
/// Defined in [RFC 8891](https://datatracker.ietf.org/doc/html/rfc8891).
pub trait Magma:
    base::KeyInit<GOST_CIPHER_KEY_LEN> + base::BlockCipher<MAGMA_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}

/// GOST R 34.12-2015 "Kuznyechik" (Grasshopper). (128-bit block, 256-bit key).
///
/// Defined in [RFC 7801](https://datatracker.ietf.org/doc/html/rfc7801).
pub trait Kuznyechik:
    base::KeyInit<GOST_CIPHER_KEY_LEN> + base::BlockCipher<KUZNYECHIK_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}

/// GOST R 34.11-2012 "Streebog" (256-bit output).
///
/// Defined in [RFC 6986](https://datatracker.ietf.org/doc/html/rfc6986).
pub trait Streebog256: base::Digest<STREEBOG256_OUT_LEN> + markers::Hash {}

/// GOST R 34.11-2012 "Streebog" (512-bit output).
///
/// Defined in [RFC 6986](https://datatracker.ietf.org/doc/html/rfc6986).
pub trait Streebog512: base::Digest<STREEBOG512_OUT_LEN> + markers::Hash {}

/// GOST R 34.11-94 (Legacy Hash Function).
///
/// Described in [RFC 4357](https://datatracker.ietf.org/doc/html/rfc4357).
pub trait Gost94: base::Digest<GOST94_OUT_LEN> + markers::Hash {}

/// GOST R 34.10-2012 (256-bit variant). Elliptic Curve Digital Signature
/// Algorithm.
///
/// Defined in [RFC 7091](https://datatracker.ietf.org/doc/html/rfc7091).
pub trait Gost3410_2012_256:
    base::SignatureScheme + markers::Asymmetric + markers::Signature + markers::EllipticCurve
{
}

/// GOST R 34.10-2012 (512-bit variant). Elliptic Curve Digital Signature
/// Algorithm.
///
/// Defined in [RFC 7091](https://datatracker.ietf.org/doc/html/rfc7091).
pub trait Gost3410_2012_512:
    base::SignatureScheme + markers::Asymmetric + markers::Signature + markers::EllipticCurve
{
}
