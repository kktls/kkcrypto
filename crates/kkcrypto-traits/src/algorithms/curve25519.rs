//! Elliptic curve cryptography over Curve25519 and Curve448.

use crate::{
    base,
    markers,
};

/// Ed25519 digital signature scheme.
///
/// Defined in [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032).
pub trait Ed25519: base::SignatureScheme + markers::Asymmetric + markers::Signature + markers::EllipticCurve {}

/// Ed448 digital signature scheme.
///
/// Defined in [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032).
pub trait Ed448: base::SignatureScheme + markers::Asymmetric + markers::Signature + markers::EllipticCurve {}

/// X25519 key exchange mechanism.
///
/// Defined in [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748).
pub trait X25519:
    base::KeyExchange + markers::Asymmetric + markers::KeyExchange + markers::EllipticCurve + markers::DiffieHellman
{
}

/// X448 key exchange mechanism.
///
/// Defined in [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748).
pub trait X448:
    base::KeyExchange + markers::Asymmetric + markers::KeyExchange + markers::EllipticCurve + markers::DiffieHellman
{
}
