//! Data Encryption Standard (DES) and Triple DES.

use crate::{
    base,
    markers,
};

/// Length of a DES block in bytes (64 bits).
pub const DES_BLOCK_LEN: usize = 8;

/// Length of a single DES key in bytes (64 bits including parity).
pub const DES_KEY_LEN: usize = 8;
/// Length of a 2-key Triple DES key in bytes (128 bits including parity).
pub const TDES_2KEY_LEN: usize = 16;
/// Length of a 3-key Triple DES key in bytes (192 bits including parity).
pub const TDES_3KEY_LEN: usize = 24;

/// DES cipher (56-bit effective key, passed as 8 bytes with parity).
///
/// Defined in [NIST FIPS 46-3](https://csrc.nist.gov/pubs/fips/46-3/final) (Withdrawn).
pub trait Des:
    base::KeyInit<DES_KEY_LEN> + base::BlockCipher<DES_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}

/// 2-key Triple DES (112-bit effective key, passed as 16 bytes).
///
/// Defined in [NIST SP 800-67 Rev. 2](https://csrc.nist.gov/pubs/sp/800/67/r2/final).
pub trait Tdes2Key:
    base::KeyInit<TDES_2KEY_LEN> + base::BlockCipher<DES_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}

/// 3-key Triple DES (168-bit effective key, passed as 24 bytes).
///
/// Defined in [NIST SP 800-67 Rev. 2](https://csrc.nist.gov/pubs/sp/800/67/r2/final).
pub trait Tdes3Key:
    base::KeyInit<TDES_3KEY_LEN> + base::BlockCipher<DES_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}
