//! Key Derivation Functions (KDFs).

use crate::{
    base,
    markers,
};

/// HMAC-based Key Derivation Function (HKDF) using SHA-256.
///
/// Defined in [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869).
pub trait HkdfSha256: base::Kdf + markers::Hash {}

/// HMAC-based Key Derivation Function (HKDF) using SHA-384.
///
/// Defined in [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869).
pub trait HkdfSha384: base::Kdf + markers::Hash {}
