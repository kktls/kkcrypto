//! Finite Field Diffie-Hellman (FFDHE) Ephemeral Key Exchange.

use crate::{
    base,
    markers,
};

/// FFDHE over the standardized 2048-bit modular exponential group.
///
/// Defined in [RFC 7919](https://datatracker.ietf.org/doc/html/rfc7919).
pub trait Ffdhe2048:
    base::KeyExchange + markers::Asymmetric + markers::KeyExchange + markers::FiniteFieldDh + markers::TraditionalMath
{
}

/// FFDHE over the standardized 3072-bit modular exponential group.
///
/// Defined in [RFC 7919](https://datatracker.ietf.org/doc/html/rfc7919).
pub trait Ffdhe3072:
    base::KeyExchange + markers::Asymmetric + markers::KeyExchange + markers::FiniteFieldDh + markers::TraditionalMath
{
}

/// FFDHE over the standardized 4096-bit modular exponential group.
///
/// Defined in [RFC 7919](https://datatracker.ietf.org/doc/html/rfc7919).
pub trait Ffdhe4096:
    base::KeyExchange + markers::Asymmetric + markers::KeyExchange + markers::FiniteFieldDh + markers::TraditionalMath
{
}
