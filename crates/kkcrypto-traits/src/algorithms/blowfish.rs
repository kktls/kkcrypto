//! Blowfish Block Cipher.

use crate::{
    base,
    markers,
};

/// Length of a Blowfish block in bytes (64 bits).
pub const BLOWFISH_BLOCK_LEN: usize = 8;

/// Blowfish block cipher. Takes a variable-length key up to 448 bits (56
/// bytes).
///
/// Defined in [Fast Software Encryption (1993)](https://www.schneier.com/academic/blowfish/).
pub trait Blowfish:
    base::VariableKeyInit
    + base::BlockCipher<BLOWFISH_BLOCK_LEN>
    + markers::Symmetric
    + markers::BlockCipher
    + markers::VariableLengthKey
{
}
