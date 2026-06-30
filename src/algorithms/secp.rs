//! NIST and SECG elliptic curves (ECDSA and ECDH).

use crate::{
    base,
    markers,
};

/// ECDSA over the NIST P-256 curve (secp256r1).
///
/// Defined in [NIST FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final).
pub trait Secp256r1Ecdsa:
    base::SignatureScheme + markers::Asymmetric + markers::Signature + markers::EllipticCurve
{
}

/// ECDH over the NIST P-256 curve (secp256r1).
///
/// Defined in [NIST SP 800-56A Rev. 3](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final).
pub trait Secp256r1Ecdh:
    base::KeyExchange + markers::Asymmetric + markers::KeyExchange + markers::EllipticCurve + markers::DiffieHellman
{
}

/// ECDSA over the SECG secp256k1 curve.
///
/// Defined in [SEC 2: Recommended Elliptic Curve Domain Parameters](https://www.secg.org/sec2-v2.pdf).
pub trait Secp256k1Ecdsa:
    base::SignatureScheme + markers::Asymmetric + markers::Signature + markers::EllipticCurve
{
}

/// ECDH over the SECG secp256k1 curve.
///
/// Defined in [SEC 2: Recommended Elliptic Curve Domain Parameters](https://www.secg.org/sec2-v2.pdf).
pub trait Secp256k1Ecdh:
    base::KeyExchange + markers::Asymmetric + markers::KeyExchange + markers::EllipticCurve + markers::DiffieHellman
{
}

/// ECDSA over the NIST P-384 curve (secp384r1).
///
/// Defined in [NIST FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final).
pub trait Secp384r1Ecdsa:
    base::SignatureScheme + markers::Asymmetric + markers::Signature + markers::EllipticCurve
{
}

/// ECDSA over the NIST P-521 curve (secp521r1).
///
/// Defined in [NIST FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final).
pub trait Secp521r1Ecdsa:
    base::SignatureScheme + markers::Asymmetric + markers::Signature + markers::EllipticCurve
{
}

/// ECDH over the NIST P-521 curve (secp521r1).
///
/// Defined in [NIST SP 800-56A Rev. 3](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final).
pub trait Secp521r1Ecdh:
    base::KeyExchange + markers::Asymmetric + markers::KeyExchange + markers::EllipticCurve + markers::DiffieHellman
{
}
