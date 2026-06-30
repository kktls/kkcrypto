//! Data Encryption Standard (DES) and Triple DES.

use crate::{
    base,
    markers,
};

/// DES cipher (56-bit effective key, passed as 8 bytes with parity).
///
/// Defined in [NIST FIPS 46-3](https://csrc.nist.gov/pubs/fips/46-3/final) (Withdrawn).
pub trait Des: base::KeyInit<8> + base::BlockCipher<8> + markers::Symmetric + markers::BlockCipher {}

/// 2-key Triple DES (112-bit effective key, passed as 16 bytes).
///
/// Defined in [NIST SP 800-67 Rev. 2](https://csrc.nist.gov/pubs/sp/800/67/r2/final).
pub trait Tdes2Key: base::KeyInit<16> + base::BlockCipher<8> + markers::Symmetric + markers::BlockCipher {}

/// 3-key Triple DES (168-bit effective key, passed as 24 bytes).
///
/// Defined in [NIST SP 800-67 Rev. 2](https://csrc.nist.gov/pubs/sp/800/67/r2/final).
pub trait Tdes3Key: base::KeyInit<24> + base::BlockCipher<8> + markers::Symmetric + markers::BlockCipher {}
