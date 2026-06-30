//! RSA public-key encryption and digital signatures.

use crate::{
    base,
    markers,
};

/// RSA encryption using OAEP padding.
///
/// Defined in [RFC 8017 (PKCS #1 v2.2)](https://datatracker.ietf.org/doc/html/rfc8017).
pub trait RsaOaep: base::PublicKeyEncryption + markers::Asymmetric + markers::TraditionalMath {}

/// RSA encryption using PKCS#1 v1.5 padding.
///
/// Defined in [RFC 8017 (PKCS #1 v2.2)](https://datatracker.ietf.org/doc/html/rfc8017).
pub trait RsaPkcs1v15Enc: base::PublicKeyEncryption + markers::Asymmetric + markers::TraditionalMath {}

/// RSA signatures using PKCS#1 v1.5 padding.
///
/// Defined in [RFC 8017 (PKCS #1 v2.2)](https://datatracker.ietf.org/doc/html/rfc8017).
pub trait RsaPkcs1v15Sig:
    base::SignatureScheme + markers::Asymmetric + markers::Signature + markers::TraditionalMath
{
}

/// RSA signatures using PSS padding.
///
/// Defined in [RFC 8017 (PKCS #1 v2.2)](https://datatracker.ietf.org/doc/html/rfc8017).
pub trait RsaPss: base::SignatureScheme + markers::Asymmetric + markers::Signature + markers::TraditionalMath {}
