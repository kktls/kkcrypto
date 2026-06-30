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

/// Password-Based Key Derivation Function 2 (PBKDF2) using HMAC-SHA1.
///
/// Defined in [RFC 8018 (PKCS #5 v2.1)](https://datatracker.ietf.org/doc/html/rfc8018).
pub trait Pbkdf2HmacSha1: base::PasswordBasedKdf + markers::Hash {}

/// Password-Based Key Derivation Function 2 (PBKDF2) using HMAC-SHA256.
///
/// Defined in [RFC 8018 (PKCS #5 v2.1)](https://datatracker.ietf.org/doc/html/rfc8018).
pub trait Pbkdf2HmacSha256: base::PasswordBasedKdf + markers::Hash {}

/// Password-Based Key Derivation Function 2 (PBKDF2) using HMAC-SHA384.
///
/// Defined in [RFC 8018 (PKCS #5 v2.1)](https://datatracker.ietf.org/doc/html/rfc8018).
pub trait Pbkdf2HmacSha384: base::PasswordBasedKdf + markers::Hash {}

/// Password-Based Key Derivation Function 2 (PBKDF2) using HMAC-SHA512.
///
/// Defined in [RFC 8018 (PKCS #5 v2.1)](https://datatracker.ietf.org/doc/html/rfc8018).
pub trait Pbkdf2HmacSha512: base::PasswordBasedKdf + markers::Hash {}

/// Key-Based Key Derivation Function (KBKDF) in Counter Mode with HMAC.
///
/// Defined in [NIST SP 800-108 Rev. 1](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final).
pub trait KbkdfCtrHmac: base::StepKdf + markers::Hash {}

/// Single-step Key Derivation Function (SSKDF) using a hash digest.
///
/// Defined in [NIST SP 800-56C Rev. 2](https://csrc.nist.gov/pubs/sp/800/56/c/r2/final).
pub trait SskdfDigest: base::StepKdf + markers::Hash {}

/// Single-step Key Derivation Function (SSKDF) using HMAC.
///
/// Defined in [NIST SP 800-56C Rev. 2](https://csrc.nist.gov/pubs/sp/800/56/c/r2/final).
pub trait SskdfHmac: base::StepKdf + markers::Hash {}
