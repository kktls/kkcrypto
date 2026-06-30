//! Digital Signature Algorithm (DSA).

use crate::{
    base,
    markers,
};

/// Traditional DSA signature scheme.
///
/// Defined in [NIST FIPS 186-4](https://csrc.nist.gov/pubs/fips/186-4/final).
pub trait Dsa: base::SignatureScheme + markers::Asymmetric + markers::Signature + markers::TraditionalMath {}
