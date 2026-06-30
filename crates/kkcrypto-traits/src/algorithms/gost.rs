//! Russian National Standard (GOST) cryptography.

use crate::{
    base,
    markers,
};

/// GOST 28147-89 / GOST R 34.12-2015 "Magma". (64-bit block, 256-bit key).
///
/// Defined in [RFC 8891](https://datatracker.ietf.org/doc/html/rfc8891).
pub trait Magma: base::KeyInit<32> + base::BlockCipher<8> + markers::Symmetric + markers::BlockCipher {}

/// GOST R 34.12-2015 "Kuznyechik" (Grasshopper). (128-bit block, 256-bit key).
///
/// Defined in [RFC 7801](https://datatracker.ietf.org/doc/html/rfc7801).
pub trait Kuznyechik: base::KeyInit<32> + base::BlockCipher<16> + markers::Symmetric + markers::BlockCipher {}

/// GOST R 34.11-2012 "Streebog" (256-bit output).
///
/// Defined in [RFC 6986](https://datatracker.ietf.org/doc/html/rfc6986).
pub trait Streebog256: base::Digest<32> + markers::Hash {}

/// GOST R 34.11-2012 "Streebog" (512-bit output).
///
/// Defined in [RFC 6986](https://datatracker.ietf.org/doc/html/rfc6986).
pub trait Streebog512: base::Digest<64> + markers::Hash {}

/// GOST R 34.11-94 (Legacy Hash Function).
///
/// Described in [RFC 4357](https://datatracker.ietf.org/doc/html/rfc4357).
pub trait Gost94: base::Digest<32> + markers::Hash {}

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
