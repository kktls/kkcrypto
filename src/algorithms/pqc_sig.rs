//! Post-Quantum Digital Signatures (NIST FIPS 204, 205).

use crate::{
    base,
    markers,
};

/// NIST FIPS 204 ML-DSA-44 (formerly Dilithium2).
///
/// Defined in [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).
pub trait MlDsa44:
    base::SignatureScheme + markers::Asymmetric + markers::Signature + markers::PostQuantum + markers::LatticeBased
{
}

/// NIST FIPS 204 ML-DSA-65 (formerly Dilithium3).
///
/// Defined in [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).
pub trait MlDsa65:
    base::SignatureScheme + markers::Asymmetric + markers::Signature + markers::PostQuantum + markers::LatticeBased
{
}

/// NIST FIPS 205 SLH-DSA (formerly SPHINCS+). Stateless hash-based signatures.
///
/// Defined in [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).
pub trait SlhDsaSha2_128s:
    base::SignatureScheme + markers::Asymmetric + markers::Signature + markers::PostQuantum + markers::HashBased
{
}
