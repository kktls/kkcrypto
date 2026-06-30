//! Elliptic curve cryptography over Curve25519 and Curve448.

use crate::{
    base,
    markers,
};

/// Length of an Ed25519 or X25519 public key in bytes (256 bits).
pub const CURVE25519_PUBKEY_LEN: usize = 32;

/// Length of an Ed448 or X448 public key in bytes (448 bits rounded to 57
/// bytes).
pub const CURVE448_PUBKEY_LEN: usize = 57;

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
