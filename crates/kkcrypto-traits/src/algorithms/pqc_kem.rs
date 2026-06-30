//! Post-Quantum Key Encapsulation Mechanisms (NIST FIPS 203 & others).

use crate::{
    base,
    markers,
};

/// NIST FIPS 203 ML-KEM-512 (formerly Kyber512).
///
/// Defined in [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).
pub trait MlKem512:
    base::Kem + markers::Asymmetric + markers::Kem + markers::PostQuantum + markers::LatticeBased
{
}

/// NIST FIPS 203 ML-KEM-768 (formerly Kyber768).
///
/// Defined in [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).
pub trait MlKem768:
    base::Kem + markers::Asymmetric + markers::Kem + markers::PostQuantum + markers::LatticeBased
{
}

/// NIST FIPS 203 ML-KEM-1024 (formerly Kyber1024).
///
/// Defined in [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).
pub trait MlKem1024:
    base::Kem + markers::Asymmetric + markers::Kem + markers::PostQuantum + markers::LatticeBased
{
}

/// Classic McEliece 348864. Highly conservative code-based KEM.
///
/// Defined in the [Classic McEliece Specification](https://classic.mceliece.org/).
pub trait McEliece348864:
    base::Kem + markers::Asymmetric + markers::Kem + markers::PostQuantum + markers::CodeBased
{
}
